from setuptools import setup, find_packages

setup(
	name='dyldextractor',
	version='2.1.2',
	description='Extract Binaries from Apple\'s Dyld Shared Cache',
	long_description='file: README.md',
	long_description_content_type='text/markdown',
	python_requires='>=3.8',
	author='arandomdev',
	url='https://github.com/arandomdev/dyldextractor',
	install_requires=['progressbar2', 'capstone==4.0.2'],
	packages=find_packages(
		where='src'
	),
	package_dir={"": "src"},
	classifiers=[
		'Programming Language :: Python :: 3',
		'License :: OSI Approved :: MIT License',
		'Operating System :: OS Independent'
	],
	scripts=['bin/dyldex', 'bin/dyldex_all']
)
