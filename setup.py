from setuptools import setup, find_packages

setup(
    name='infiltra',
    version='2.1',
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
        # If your package is named 'infiltra', and you have non-code files in it:
        'infiltra': ['*.json', '*.sh', '*.yaml', '*.png', 'venv/*', 'eyewitness/*', 'bbot/*', 'aort/*'],
    },

    # Metadata
    author='@jivy26',
    author_email='jivy26@gmail.com',
    description='CLI Based to that Automates Various Pentest Tools',
    license='MIT',  # This must match the license file you have
    keywords='infiltra penetration cybersecurity scanning',
)