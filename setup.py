from setuptools import setup

setup(
    name='cloud_enum',
    description='Multi-cloud OSINT tool. Enumerate public resources in AWS, Azure, and Google Cloud.',
    author='initstring',
    url='https://github.com/initstring/cloud_enum',
    license='MIT',
    packages=[
        'enum_tools'
    ],
    py_modules=[
        'cloud_enum'
    ],
    install_requires=[
        'dnspython',
        'requests',
        'requests_futures'
    ],
    python_requires='>=3.0.0',
    entry_points={
        'console_scripts': [
            'cloud_enum = cloud_enum:main'
        ]
    }
)
