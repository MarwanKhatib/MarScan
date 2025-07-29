import os
from setuptools import setup, find_packages

# Read the version from the __init__.py file
with open(os.path.join('marscan', '__init__.py')) as f:
    for line in f:
        if line.startswith('__version__'):
            version = line.split('=')[1].strip().strip('"')
            break

setup(
    name='marscan',
    version=version,
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'rich>=13.0.0',
        'rich-argparse>=1.0.0',
        'scapy>=2.4.5',
        'pyfiglet>=0.8.post1',
        'markdown-it-py>=2.1.0',
        'mdurl>=0.1.0',
        'Pygments>=2.12.0',
    ],
    entry_points={
        'console_scripts': [
            'marscan=marscan.main:main',
        ],
    },
    author='Marwan ALkhatib',
    author_email='marwanalkhatibeh@gmail.com', 
    description='A blazing-fast, lightweight Python port scanner for ethical hackers and red teamers.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/MarwanKhatib/MarScan',
    keywords=['port-scanner', 'security', 'network', 'pentesting', 'hacking'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Topic :: System :: Networking',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.8',
)
