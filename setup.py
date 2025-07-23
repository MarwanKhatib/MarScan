from setuptools import setup, find_packages

setup(
    name='marscan',
    version='0.1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'rich',
    ],
    entry_points={
        'console_scripts': [
            'marscan=marscan.main:main',
        ],
    },
    author='MarwanKhatib', # Placeholder, user can update
    description='A blazing-fast, lightweight Python port scanner for ethical hackers and red teamers.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/MarwanKhatib/MarScan', # Placeholder, user can update
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Security',
        'Topic :: System :: Networking',
    ],
    python_requires='>=3.6',
)
