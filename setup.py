from setuptools import setup, find_packages

setup(
    name='infiltra',
    version='2.3',
    packages=find_packages(),
    install_requires=[
        'colorama',
    ],
    entry_points={
        'console_scripts': [
            'infiltra=infiltra.ept:main',
        ],
    },
    # Include additional files into the package
    include_package_data=True,
    package_data={
        'infiltra': [
            'aort/utils/*.json',
            'version.txt',
            '*.json',
            '*.sh',
            '*.yaml',
            '*.png',
            'venv/*',
            'eyewitness/*',
            'bbot/*',
            'aort/*',
            'nuclei-templates/**/*',
        ],
    },
    # Metadata
    author='@jivy26',
    author_email='jivy26@gmail.com',
    description='CLI Based to that Automates Various Pentest Tools',
    license='MIT',
    keywords='infiltra penetration cybersecurity scanning',
)