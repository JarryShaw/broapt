===============
Basic Framework
===============

.. toctree::
   :maxdepth: 3

   framework.core
   framework.app

The BroAPT system is generally designed in two main parts, as we described in the
:doc:`introduction </index>`, the core functions and the daemon server with its
command line interface (CLI).

.. image:: _image/BroAPT/BroAPT.003.png
   :alt: BroAPT Framework

On the host machine, the BroAPT-Daemon server runs as a manager of the BtoAPT
system, which watches the running status of underlying BroAPT core functions,
i.e. BroAPT-Core and BroAPT-App frameworks, as well as perform *remote* detection
upon API requests from detection framework.

In the docker containers, the BroAPT-Core and BroAPT-App frameworks perform
the core functions of BroAPT system. They analyse source PCAP files and extract
files transferred through the traffic with `Bro IDS`_, then detect the extracted
files based on MIME type specifically configured APT detection methods.

.. _Bro IDS: https://www.zeek.org

The general process of processing is as following:

.. image:: _image/BroAPT/BroAPT.005.png
   :alt: BroAPT Multiprocessing Framework

0. When the BroAPT-Core framework first reads a new PCAP file, it will utilise
   Bro IDS to process it, extract files transferred and perform other actions
   as configured through the Bro site functions.
1. As files had been extracted, the BroAPT-App framework will perform malware
   detection on each file. If *remote* detection configured, it will send an
   API request to the BroAPT-Daemon server, and wait for its detection report.
2. At the same time, once the Bro processing had finished, the BroAPT-Core
   framework will start processing the generated logs, and perform extra analysis
   over the Bro log files as specified by the Python hooks.
3. When the BroAPT-Daemon receives an API request, it will perform malware
   detection as described in the request, and send the detection report
   back to the BroAPT-App framework.
