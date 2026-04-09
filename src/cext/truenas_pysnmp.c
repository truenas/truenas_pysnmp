// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <sys/stat.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/snmpusm.h>

#define MODULE_NAME "truenas_pysnmp._native"
#define MODULE_DOC "TrueNAS SNMP C extension using net-snmp"
#define SNMP_APP_NAME "truenas_pysnmp"

/* Mandatory varbind OIDs required by every SNMPv2 trap (RFC 3416) */
static const oid oid_sysuptime[] = { 1,3,6,1,2,1,1,3,0 };
static const oid oid_snmptrapoid[] = { 1,3,6,1,6,3,1,1,4,1,0 };

/*
 * TrueNAS notification OIDs from TRUENAS-MIB.
 * See: middleware/src/freenas/usr/local/share/snmp/mibs/TRUENAS-MIB.txt
 */
static const oid oid_alert[] = { 1,3,6,1,4,1,50536,2,1,1 };
static const oid oid_alert_cancellation[] = { 1,3,6,1,4,1,50536,2,1,2 };

/* TrueNAS notification payload OIDs (scalar instances, hence .0) */
static const oid oid_alert_id[] = { 1,3,6,1,4,1,50536,2,2,1,0 };
static const oid oid_alert_level[] = { 1,3,6,1,4,1,50536,2,2,2,0 };
static const oid oid_alert_message[] = { 1,3,6,1,4,1,50536,2,2,3,0 };

#define PERSIST_DIR "/data/subsystems/snmp"
#define PERSIST_FILE PERSIST_DIR "/truenas_pysnmp.conf"

/* Module state */
typedef struct {
	PyObject *SNMPError;
	u_char *engine_id;
	size_t engine_id_len;
	time_t config_mtime;
} pysnmp_state_t;

static PyModuleDef pysnmp_module;

static pysnmp_state_t *
get_pysnmp_state(PyObject *module)
{
	if (module == NULL) {
		module = PyState_FindModule(&pysnmp_module);
		if (module == NULL)
			return NULL;
	}
	return (pysnmp_state_t *)PyModule_GetState(module);
}

static time_t
get_config_mtime(void)
{
	struct stat st;
	return (stat(PERSIST_FILE, &st) == 0) ? st.st_mtime : 0;
}

/* Re-read engine ID if persistent file changed */
static void
reload_engine_id_if_needed(pysnmp_state_t *state)
{
	time_t mtime = get_config_mtime();
	if (mtime == state->config_mtime)
		return;

	state->config_mtime = mtime;
	free(state->engine_id);
	state->engine_id = NULL;
	state->engine_id_len = 0;
	free_engineID(0, 0, NULL, NULL);
	read_config_with_type(PERSIST_FILE, SNMP_APP_NAME);
	setup_engineID(NULL, NULL);
	state->engine_id = snmpv3_generate_engineID(&state->engine_id_len);
}

#define TRAP_ERR_SIZE 512

/* Error reporting for C functions that run without the Python GIL */
typedef struct {
	int failed;
	char message[TRAP_ERR_SIZE];
} trap_error_t;

static void
trap_err_set(trap_error_t *err, const char *fmt, ...)
{
	va_list ap;
	err->failed = 1;
	va_start(ap, fmt);
	vsnprintf(err->message, TRAP_ERR_SIZE, fmt, ap);
	va_end(ap);
}

/* Map level name to MIB integer (1-7). Returns 0 on unknown.
 * Must stay in sync with AlertLevel in stubs/constants.py */
static int
alert_level_from_string(const char *level)
{
	static const struct {
		const char *name;
		int value;
	} levels[] = {
		{ "info",      1 },
		{ "notice",    2 },
		{ "warning",   3 },
		{ "error",     4 },
		{ "critical",  5 },
		{ "alert",     6 },
		{ "emergency", 7 },
	};

	for (size_t i = 0; i < sizeof(levels) / sizeof(levels[0]); i++) {
		if (strcmp(level, levels[i].name) == 0)
			return levels[i].value;
	}
	return 0;
}

/* Free v3 fields allocated on a stack session. NULL-safe. */
static void
free_v3_session_fields(netsnmp_session *session)
{
	free(session->securityEngineID);
	session->securityEngineID = NULL;
	free(session->contextEngineID);
	session->contextEngineID = NULL;
}

/* Auth protocol lookup table. Must stay in sync with V3AuthProtocol in stubs/constants.py */
typedef struct {
	const char *name;
	const oid  *proto;
	size_t      proto_len;
} proto_map_t;

static const proto_map_t auth_protocols[] = {
	{ "MD5",      usmHMACMD5AuthProtocol,       USM_AUTH_PROTO_MD5_LEN },
#ifdef USM_AUTH_PROTO_SHA_LEN
	{ "SHA",      usmHMACSHA1AuthProtocol,       USM_AUTH_PROTO_SHA_LEN },
#endif
#ifdef HAVE_EVP_SHA224
	{ "128SHA224", usmHMAC128SHA224AuthProtocol, sizeof(usmHMAC128SHA224AuthProtocol) / sizeof(oid) },
	{ "192SHA256", usmHMAC192SHA256AuthProtocol, sizeof(usmHMAC192SHA256AuthProtocol) / sizeof(oid) },
	{ "256SHA384", usmHMAC256SHA384AuthProtocol, sizeof(usmHMAC256SHA384AuthProtocol) / sizeof(oid) },
	{ "384SHA512", usmHMAC384SHA512AuthProtocol, sizeof(usmHMAC384SHA512AuthProtocol) / sizeof(oid) },
#endif
	{ NULL, NULL, 0 }
};

/* Priv protocol lookup table. Must stay in sync with V3PrivProtocol in stubs/constants.py */
static const proto_map_t priv_protocols[] = {
	{ "DES",       usmDESPrivProtocol,  USM_PRIV_PROTO_DES_LEN },
#ifdef USM_PRIV_PROTO_AES128_LEN
	{ "AESCFB128", usmAESPrivProtocol,  USM_PRIV_PROTO_AES128_LEN },
#endif
#ifdef USM_CREATE_USER_PRIV_AES192
	{ "AESCFB192", usmAES192PrivProtocol, sizeof(usmAES192PrivProtocol) / sizeof(oid) },
#endif
#ifdef USM_CREATE_USER_PRIV_AES256
	{ "AESCFB256", usmAES256PrivProtocol, sizeof(usmAES256PrivProtocol) / sizeof(oid) },
#endif
	{ NULL, NULL, 0 }
};

/* Find a protocol by name in a lookup table. Returns NULL if not found. */
static const proto_map_t *
find_protocol(const proto_map_t *table, const char *name)
{
	for (const proto_map_t *p = table; p->name != NULL; p++) {
		if (strcmp(name, p->name) == 0)
			return p;
	}
	return NULL;
}

/*
 * Configure SNMPv3 session: auth/priv protocols, keys, engine ID.
 * Returns 0 on success, -1 on error. Caller frees via free_v3_session_fields().
 */
static int
configure_v3_session(netsnmp_session *session,
		     const char *username,
		     const char *authprotocol,
		     const char *authkey,
		     const char *privprotocol,
		     const char *privkey,
		     const u_char *engine_id,
		     size_t engine_id_len,
		     trap_error_t *err)
{
	const u_char *eid;
	size_t eid_len;
	const proto_map_t *proto;

	session->version = SNMP_VERSION_3;
	/* snmp_add() strdup's securityName internally */
	session->securityName = (char *)username;
	session->securityNameLen = strlen(username);

	/* Auth protocol */
	if (authprotocol == NULL || authprotocol[0] == '\0') {
		session->securityLevel = SNMP_SEC_LEVEL_NOAUTH;
		session->securityAuthProto = (oid *)usmNoAuthProtocol;
		session->securityAuthProtoLen = USM_AUTH_PROTO_NOAUTH_LEN;
	} else {
		proto = find_protocol(auth_protocols, authprotocol);
		if (proto == NULL) {
			trap_err_set(err, "Unsupported auth protocol: %s", authprotocol);
			return -1;
		}
		session->securityAuthProto = (oid *)proto->proto;
		session->securityAuthProtoLen = proto->proto_len;
		session->securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;

		session->securityAuthKeyLen = USM_AUTH_KU_LEN;
		if (generate_Ku(session->securityAuthProto,
				session->securityAuthProtoLen,
				(const u_char *)authkey, strlen(authkey),
				session->securityAuthKey,
				&session->securityAuthKeyLen) != SNMPERR_SUCCESS) {
			trap_err_set(err, "Failed to generate auth key");
			return -1;
		}
	}

	/* Priv protocol */
	if (privprotocol != NULL && privprotocol[0] != '\0') {
		if (session->securityLevel < SNMP_SEC_LEVEL_AUTHNOPRIV) {
			trap_err_set(err, "Privacy requires authentication");
			return -1;
		}
		proto = find_protocol(priv_protocols, privprotocol);
		if (proto == NULL) {
			trap_err_set(err, "Unsupported priv protocol: %s", privprotocol);
			return -1;
		}
		session->securityPrivProto = (oid *)proto->proto;
		session->securityPrivProtoLen = proto->proto_len;
		session->securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;

		session->securityPrivKeyLen = USM_PRIV_KU_LEN;
		if (generate_Ku(session->securityAuthProto,
				session->securityAuthProtoLen,
				(const u_char *)privkey, strlen(privkey),
				session->securityPrivKey,
				&session->securityPrivKeyLen) != SNMPERR_SUCCESS) {
			trap_err_set(err, "Failed to generate priv key");
			return -1;
		}
	}

	/* Engine ID setup */
	eid = engine_id;
	eid_len = engine_id_len;
	session->securityEngineID = netsnmp_memdup(eid, eid_len);
	if (session->securityEngineID == NULL) {
		trap_err_set(err, "Failed to allocate security engine ID");
		return -1;
	}
	session->securityEngineIDLen = eid_len;

	session->contextEngineID = netsnmp_memdup(eid, eid_len);
	if (session->contextEngineID == NULL) {
		trap_err_set(err, "Failed to allocate context engine ID");
		return -1;
	}
	session->contextEngineIDLen = eid_len;

	/* Use epoch time so engineTime always increases across HA failovers */
	session->engineBoots = 1;
	session->engineTime = (long)time(NULL);
	set_enginetime(session->securityEngineID,
		       session->securityEngineIDLen,
		       session->engineBoots,
		       session->engineTime, TRUE);

	/* Force snmp_add() to use this session's keys, not previously cached ones */
	struct usmUser *old_user = usm_get_user(eid, eid_len, username);
	if (old_user != NULL) {
		/* usm_remove_user returns the list head, not the removed user */
		usm_remove_user(old_user);
		usm_free_user(old_user);
	}

	return 0;
}

/*
 * Build and send an SNMP trap PDU. Runs without the GIL.
 * Returns 0 on success, -1 on error (trap_error_t set).
 */
static int
send_trap(const char *host, int port,
	  int version, const char *community,
	  const char *v3_username, const char *v3_authprotocol,
	  const char *v3_authkey, const char *v3_privprotocol,
	  const char *v3_privkey,
	  const u_char *engine_id, size_t engine_id_len,
	  const oid *trap_oid, size_t trap_oid_len,
	  const char *alert_id,
	  int level, const char *message,
	  trap_error_t *err)
{
	netsnmp_session session, *ss = NULL;
	netsnmp_pdu *pdu = NULL;
	netsnmp_transport *transport = NULL;
	char peername[280];
	long sysuptime = 0;
	int ret = -1;

	err->failed = 0;
	err->message[0] = '\0';

	snprintf(peername, sizeof(peername), "%s:%d", host, port);

	snmp_sess_init(&session);
	session.peername = peername;

	if (version == SNMP_VERSION_3) {
		if (configure_v3_session(&session, v3_username,
					v3_authprotocol, v3_authkey,
					v3_privprotocol, v3_privkey,
					engine_id, engine_id_len,
					err) < 0)
			goto out;
	} else {
		session.version = SNMP_VERSION_2c;
		session.community = (u_char *)community;
		session.community_len = strlen(community);
	}

	/* Open session with "snmptrap" transport (matches upstream snmptrap.c) */
	transport = netsnmp_transport_open_client("snmptrap", peername);
	if (transport == NULL) {
		trap_err_set(err, "Failed to open transport to %s", peername);
		goto out;
	}
	ss = snmp_add(&session, transport, NULL, NULL);
	if (ss == NULL) {
		char *snmp_err = NULL;
		snmp_error(&session, NULL, NULL, &snmp_err);
		trap_err_set(err, "Failed to open SNMP session: %s",
			     snmp_err ? snmp_err : "unknown error");
		free(snmp_err);
		goto out;
	}

	pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
	if (pdu == NULL) {
		trap_err_set(err, "Failed to create SNMP PDU");
		goto out;
	}

	/* Mandatory varbind 1: sysUpTime.0 */
	snmp_pdu_add_variable(pdu,
		oid_sysuptime, OID_LENGTH(oid_sysuptime),
		ASN_TIMETICKS, (const u_char *)&sysuptime, sizeof(sysuptime));

	/* Mandatory varbind 2: snmpTrapOID.0 */
	snmp_pdu_add_variable(pdu,
		oid_snmptrapoid, OID_LENGTH(oid_snmptrapoid),
		ASN_OBJECT_ID, (const u_char *)trap_oid, trap_oid_len * sizeof(oid));

	/* alertId (always present) */
	snmp_pdu_add_variable(pdu,
		oid_alert_id, OID_LENGTH(oid_alert_id),
		ASN_OCTET_STR, (const u_char *)alert_id, strlen(alert_id));

	/* alertLevel (only for alert, not cancellation) */
	if (level > 0) {
		long level_val = level;
		snmp_pdu_add_variable(pdu,
			oid_alert_level, OID_LENGTH(oid_alert_level),
			ASN_INTEGER, (const u_char *)&level_val, sizeof(level_val));
	}

	/* alertMessage (only for alert, not cancellation) */
	if (message != NULL) {
		snmp_pdu_add_variable(pdu,
			oid_alert_message, OID_LENGTH(oid_alert_message),
			ASN_OCTET_STR, (const u_char *)message, strlen(message));
	}

	if (!snmp_send(ss, pdu)) {
		char *snmp_err = NULL;
		snmp_error(ss, NULL, NULL, &snmp_err);
		trap_err_set(err, "Failed to send SNMP trap: %s",
			     snmp_err ? snmp_err : "unknown error");
		free(snmp_err);
		goto out;
	}
	pdu = NULL; /* snmp_send() freed PDU on success */
	ret = 0;

out:
	if (pdu != NULL)
		snmp_free_pdu(pdu);
	if (ss != NULL)
		snmp_close(ss);
	/* Our session fields are separate copies from snmp_add()'s internal state */
	if (version == SNMP_VERSION_3)
		free_v3_session_fields(&session);
	return ret;
}

/* ---- Python-facing functions (GIL held) ---- */

/* Common parsed args for trap sending */
typedef struct {
	const char *host;
	int port;
	const char *community;
	int v3;
	const char *v3_username;
	const char *v3_authprotocol;
	const char *v3_authkey;
	const char *v3_privprotocol;
	const char *v3_privkey;
	const char *engine_id;
	Py_ssize_t engine_id_len;
	const char *alert_id;
} trap_args_t;

#define TRAP_ARGS_INIT { NULL, 0, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL }

/* Validate trap args. Returns -1 with Python exception set on error. */
static int
validate_trap_args(const trap_args_t *ta, int is_cancellation,
		   const char *level_str, const char *message)
{
	if (ta->host == NULL) {
		PyErr_SetString(PyExc_TypeError, "host is required");
		return -1;
	}

	if (ta->port < 1 || ta->port > 65535) {
		PyErr_Format(PyExc_ValueError,
			     "port must be in range 1-65535, got %d", ta->port);
		return -1;
	}

	if (ta->alert_id == NULL) {
		PyErr_SetString(PyExc_TypeError, "alert_id is required");
		return -1;
	}

	if (!ta->v3 && (ta->community == NULL || ta->community[0] == '\0')) {
		PyErr_SetString(PyExc_ValueError,
				"community is required for SNMPv2c");
		return -1;
	}

	if (ta->v3 && (ta->v3_username == NULL || ta->v3_username[0] == '\0')) {
		PyErr_SetString(PyExc_ValueError,
				"v3_username is required for SNMPv3");
		return -1;
	}

	if (ta->v3 && ta->v3_authprotocol != NULL && ta->v3_authprotocol[0] != '\0') {
		if (ta->v3_authkey == NULL || ta->v3_authkey[0] == '\0') {
			PyErr_SetString(PyExc_ValueError,
					"v3_authkey is required when v3_authprotocol is set");
			return -1;
		}
	}

	if (ta->v3 && ta->v3_privprotocol != NULL && ta->v3_privprotocol[0] != '\0') {
		if (ta->v3_privkey == NULL || ta->v3_privkey[0] == '\0') {
			PyErr_SetString(PyExc_ValueError,
					"v3_privkey is required when v3_privprotocol is set");
			return -1;
		}
	}

	if (!is_cancellation) {
		if (level_str == NULL) {
			PyErr_SetString(PyExc_TypeError, "level is required");
			return -1;
		}
		if (alert_level_from_string(level_str) == 0) {
			PyErr_Format(PyExc_ValueError,
				     "Invalid alert level: '%s'", level_str);
			return -1;
		}
		if (message == NULL) {
			PyErr_SetString(PyExc_TypeError, "message is required");
			return -1;
		}
	}

	return 0;
}

/* Send trap and handle result. */
static PyObject *
dispatch_trap(trap_args_t *ta,
	      const oid *trap_oid, size_t trap_oid_len,
	      int level, const char *message)
{
	trap_error_t err;
	int ret;
	const u_char *eid = (const u_char *)ta->engine_id;
	size_t eid_len = ta->engine_id_len;

	/* Resolve engine_id fallback while GIL is held (v3 only) */
	if (ta->v3 && (eid == NULL || eid_len == 0)) {
		pysnmp_state_t *state = get_pysnmp_state(NULL);
		if (state == NULL) {
			PyErr_SetString(PyExc_RuntimeError, "Module state not available");
			return NULL;
		}
		reload_engine_id_if_needed(state);
		eid = state->engine_id;
		eid_len = state->engine_id_len;
		if (eid == NULL || eid_len == 0) {
			PyErr_SetString(PyExc_RuntimeError, "Engine ID not available");
			return NULL;
		}
	}

	Py_BEGIN_ALLOW_THREADS
	ret = send_trap(ta->host, ta->port,
			ta->v3 ? SNMP_VERSION_3 : SNMP_VERSION_2c, ta->community,
			ta->v3_username, ta->v3_authprotocol, ta->v3_authkey,
			ta->v3_privprotocol, ta->v3_privkey,
			eid, eid_len,
			trap_oid, trap_oid_len,
			ta->alert_id, level, message, &err);
	Py_END_ALLOW_THREADS

	if (ret < 0) {
		pysnmp_state_t *state = get_pysnmp_state(NULL);
		PyErr_SetString(state ? state->SNMPError : PyExc_RuntimeError,
				err.message);
		return NULL;
	}

	Py_RETURN_NONE;
}

PyDoc_STRVAR(send_alert__doc__,
"send_alert(*, host, port, community=None, v3=False, v3_username=None,\n"
"           v3_authprotocol=None, v3_authkey=None, v3_privprotocol=None,\n"
"           v3_privkey=None, engine_id=None, alert_id, level,\n"
"           message) -> None\n"
"\n"
"Send a TrueNAS alert SNMP trap notification.\n"
);

static PyObject *
py_send_alert(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"host", "port", "community",
		"v3", "v3_username", "v3_authprotocol",
		"v3_authkey", "v3_privprotocol", "v3_privkey",
		"engine_id",
		"alert_id", "level", "message", NULL
	};

	trap_args_t ta = TRAP_ARGS_INIT;
	const char *level_str = NULL;
	const char *message = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$sizpzzzzzz#sss", kwlist,
					 &ta.host, &ta.port, &ta.community,
					 &ta.v3, &ta.v3_username, &ta.v3_authprotocol,
					 &ta.v3_authkey, &ta.v3_privprotocol, &ta.v3_privkey,
					 &ta.engine_id, &ta.engine_id_len,
					 &ta.alert_id, &level_str, &message))
		return NULL;

	if (validate_trap_args(&ta, 0, level_str, message) < 0)
		return NULL;

	return dispatch_trap(&ta, oid_alert, OID_LENGTH(oid_alert),
			     alert_level_from_string(level_str), message);
}

PyDoc_STRVAR(send_alert_cancellation__doc__,
"send_alert_cancellation(*, host, port, community=None, v3=False,\n"
"                        v3_username=None, v3_authprotocol=None,\n"
"                        v3_authkey=None, v3_privprotocol=None,\n"
"                        v3_privkey=None, engine_id=None,\n"
"                        alert_id) -> None\n"
"\n"
"Send a TrueNAS alert cancellation SNMP trap notification.\n"
);

static PyObject *
py_send_alert_cancellation(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"host", "port", "community",
		"v3", "v3_username", "v3_authprotocol",
		"v3_authkey", "v3_privprotocol", "v3_privkey",
		"engine_id",
		"alert_id", NULL
	};

	trap_args_t ta = TRAP_ARGS_INIT;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$sizpzzzzzz#s", kwlist,
					 &ta.host, &ta.port, &ta.community,
					 &ta.v3, &ta.v3_username, &ta.v3_authprotocol,
					 &ta.v3_authkey, &ta.v3_privprotocol, &ta.v3_privkey,
					 &ta.engine_id, &ta.engine_id_len,
					 &ta.alert_id))
		return NULL;

	if (validate_trap_args(&ta, 1, NULL, NULL) < 0)
		return NULL;

	return dispatch_trap(&ta, oid_alert_cancellation,
			     OID_LENGTH(oid_alert_cancellation), 0, NULL);
}

PyDoc_STRVAR(get_engine_id__doc__,
"get_engine_id() -> bytes\n"
"\n"
"Return the SNMPv3 engine ID.\n"
);

static PyObject *
py_get_engine_id(PyObject *self, PyObject *Py_UNUSED(args))
{
	pysnmp_state_t *state = get_pysnmp_state(NULL);
	if (state == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "Module state not available");
		return NULL;
	}
	reload_engine_id_if_needed(state);
	if (state->engine_id == NULL || state->engine_id_len == 0) {
		PyErr_SetString(PyExc_RuntimeError, "Engine ID not initialized");
		return NULL;
	}
	return PyBytes_FromStringAndSize((const char *)state->engine_id,
					 state->engine_id_len);
}

static PyMethodDef pysnmp_methods[] = {
	{
		.ml_name = "send_alert",
		.ml_meth = (PyCFunction)py_send_alert,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = send_alert__doc__,
	},
	{
		.ml_name = "send_alert_cancellation",
		.ml_meth = (PyCFunction)py_send_alert_cancellation,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = send_alert_cancellation__doc__,
	},
	{
		.ml_name = "get_engine_id",
		.ml_meth = (PyCFunction)py_get_engine_id,
		.ml_flags = METH_NOARGS,
		.ml_doc = get_engine_id__doc__,
	},
	{ NULL, NULL, 0, NULL }
};

static void
pysnmp_module_free(void *mod)
{
	pysnmp_state_t *state = (pysnmp_state_t *)PyModule_GetState((PyObject *)mod);
	if (state != NULL) {
		free(state->engine_id);
		state->engine_id = NULL;
		state->engine_id_len = 0;
		Py_CLEAR(state->SNMPError);
	}
	snmp_shutdown(SNMP_APP_NAME);
	SOCK_CLEANUP;
}

static PyModuleDef pysnmp_module = {
	PyModuleDef_HEAD_INIT,
	.m_name = MODULE_NAME,
	.m_doc = MODULE_DOC,
	.m_size = sizeof(pysnmp_state_t),
	.m_methods = pysnmp_methods,
	.m_free = pysnmp_module_free,
};

PyMODINIT_FUNC
PyInit__native(void)
{
	PyObject *mod;
	pysnmp_state_t *state;

	mod = PyModule_Create(&pysnmp_module);
	if (mod == NULL)
		return NULL;

	state = get_pysnmp_state(mod);
	if (state == NULL) {
		Py_DECREF(mod);
		return NULL;
	}

	SOCK_STARTUP;
	/* Persist engine ID in /data/subsystems/snmp/ to survive upgrades */
	(void)mkdir(PERSIST_DIR, 0755);
	netsnmp_ds_set_string(NETSNMP_DS_LIBRARY_ID,
			      NETSNMP_DS_LIB_PERSISTENT_DIR, PERSIST_DIR);
	init_snmp(SNMP_APP_NAME);
	/* Flush engine ID to persistent file so other processes can read it */
	snmp_store(SNMP_APP_NAME);

	setup_engineID(NULL, NULL);
	state->engine_id = snmpv3_generate_engineID(&state->engine_id_len);
	if (state->engine_id == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
				"Failed to generate SNMPv3 engine ID");
		Py_DECREF(mod);
		return NULL;
	}
	state->config_mtime = get_config_mtime();

	state->SNMPError = PyErr_NewException(MODULE_NAME ".SNMPError",
					      PyExc_RuntimeError, NULL);
	if (state->SNMPError == NULL) {
		Py_DECREF(mod);
		return NULL;
	}
	if (PyModule_AddObjectRef(mod, "SNMPError", state->SNMPError) < 0) {
		Py_DECREF(state->SNMPError);
		Py_DECREF(mod);
		return NULL;
	}

	return mod;
}
