from setuptools import setup, find_packages

setup(
    name='infiltra',
    version='3.5',
    packages=find_packages(),
    install_requires=[
        'colorama',
        'rich',
        'pydig',
        'ascii_magic',
        'pyfiglet',
        'pipx'
    ],
    entry_points={
        'console_scripts': [
            'infiltra=infiltra.infiltra:main',
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
            '*.py',
            'venv/*',
            'eyewitness/*',
            'bbot/*',
            'aort/*',
            'website_enum/*'
            'submenus/*'
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