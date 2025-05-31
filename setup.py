from setuptools import setup, find_packages

setup(
    name='mistborn',
    version='0.1.0',
    author='mistborn',
    author_email='xxxxxxxxxxx',
    description='A tool that analyzes pull requests for security vulnerabilities using OpenAI ChatGPT prompt engineering.',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    install_requires=[
        'openai',  # For using OpenAI's API
        'requests',  # For making HTTP requests
        'pytest',  # For testing
        'Flask',   # For web interface
        'python-dotenv',  # For managing environment variables
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
