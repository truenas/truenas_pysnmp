from setuptools import setup, Extension

truenas_pysnmp_ext = Extension(
    'truenas_pysnmp._native',
    sources=['src/cext/truenas_pysnmp.c'],
    include_dirs=['src/cext'],
    libraries=['netsnmp'],
)

setup(
    ext_modules=[truenas_pysnmp_ext],
    packages=['truenas_pysnmp'],
    package_dir={
        'truenas_pysnmp': 'stubs',
    },
    package_data={
        'truenas_pysnmp': ['*.pyi', 'py.typed'],
    },
)
