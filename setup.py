from setuptools import setup, find_packages
setup(name="pnio_dcp",
      use_scm_version=True,
      setup_requires=['setuptools_scm'],
      description='Structure based on DCP protocol to discover and configure devices in the network',
      url='https://cw-gitlab.codewerk.de/shacks/python/cw_dcp.git',
      author='Vladyslava Lazepka',
      author_email='vlada.lazepka@codewerk.de',
      license='Copyright (c) 2020 Codewerk GmbH, Karlsruhe.',
      packages=find_packages(),
      install_requires=['scapy', 'psutil', 'setuptools_scm'],
      zip_safe=False)
