==========
Quickstart
==========

Installation
============

Installation of the BroAPT system is rather simple. Just clone the repository
or download the tarball, then voilà, it's ready to go.

.. code:: shell

   # from GitHub (active repository)
   git clone https://github.com/JarryShaw/BroAPT.git
   # or from GitLab (authentication required)
   git clone https://gitlab.sjtu.edu.cn/bysj/2019bysj.git

Usage
=====

-------------------
``broaptd`` Service
-------------------

On Linux systems, you can register a System V service for ``broaptd``, the
main entrypoint of the BroAPT system, a.k.a the CLI of BroAPT-Daemon server.

.. important::

   We suppose you're installing ``broaptd`` on a CentOS or similar distribution.
   For macOS binaries and Docker Compose, you may find them with ``darwin`` suffix.

   For macOS services, you can register through the Launch Agent of macOS system.
   See :manpage:`launchd(8)` and :manpage:`launchd.plist(5)` for more information.

0. Install the ``broaptd`` binary:

   .. code:: shell

      # from bundled implementation
      sudo cp source/server/bin/broapt.linux /usr/local/bin/broaptd
      # from cluster implementation
      sudo cp cluster/daemon/bin/broapt.linux /usr/local/bin/broaptd

   The binary is built using ``PyInstaller``. Should you wish to build a suitable
   binary for your target system, please refer to the ``.spec`` files at
   ``source/server/spec/`` (for bundled implementation) or ``cluster/daemon/spec/``
   (for cluster implementation).

1. Create a *dotenv* file named ``/etc/sysconfig/broaptd``:

   .. code::

      ## daemon kill signal
      BROAPT_KILL_SIGNAL=15  # TERM

      ## BroAPT-Daemon server
      BROAPT_SERVER_HOST="127.0.0.1"
      BROAPT_SERVER_PORT=5000

      ## path to BroAPT's docker-compose.yml
      # for bundled implementation
      BROAPT_DOCKER_COMPOSE="/path/to/broapt/source/docker/docker-compose.linux.yml"
      # for cluster implementation
      BROAPT_DOCKER_COMPOSE="/path/to/broapt/cluster/docker/docker-compose.linux.yml"

      ## path to extract files
      BROAPT_DUMP_PATH="/path/to/extract/file/"
      ## path to log files
      BROAPT_LOGS_PATH="/path/to/log/bro/"
      ## path to detection APIs
      # for bundled implementation
      BROAPT_API_ROOT="/path/to/broapt/source/client/include/api/"
      # for cluster implementation
      BROAPT_API_ROOT="/path/to/broapt/cluster/app/include/api/"
      ## path to API runtime logs
      BROAPT_API_LOGS="/path/to/log/bro/api/"

      ## sleep interval
      BROAPT_INTERVAL=10
      ## command retry
      BROAPT_MAX_RETRY=3

2. Create a System V service file at ``/etc/systemd/system/broaptd.service``
   (works on Ubuntu 18.04):

   .. code:: ini

      [Unit]
      Description=BroAPT Daemon

      [Service]
      ExecStart=/usr/local/bin/broaptd --env /etc/sysconfig/broaptd
      ExecReload=/usr/bin/kill -INT $MAINPID
      Restart=always
      RestartSec=60s

      [Install]
      WantedBy=multi-user.target

3. Reload daemon and enable ``broaptd`` service:

   .. code:: shell

      sudo systemctl daemon-reload
      sudo systemctl enable broaptd.service

   You may wish to check if its running now:

   .. code:: shell

      sudo systemctl status broaptd.service

--------------
Docker Compose
--------------

Even though the ``broaptd`` will already manage the Docker containers of
the BroAPT system through Docker Compose, you might wish to check by yourself.

Bundled Implementation
----------------------

For bundled implementation, there is only one Docker container service called
``broapt``. You can refer to the Docker Compose file at ``source/docker/docker-compose.${system}.yml``.

Cluster Implementation
----------------------

For cluster implementation, there are two Docker container services: ``core``
for the BroAPT-Core framework and ``app`` for the BroAPT-App framework. You
can refer to the Docker Compose file at ``cluster/docker/docker-compose.${system}.yml``.

Repository Structure
====================

.. code:: text

   /broapt/
   ├── LICENSE             # CC license
   ├── LICENSE.bsd         # BSD license
   ├── cluster             # cluster (standalone) implementation
   │   └── ...
   ├── docs
   │   ├── broaptd.8       # manual for BroAPT-Daemon
   │   ├── thesis.pdf      # Bachelor's Thesis
   │   └── ...
   ├── gitlab              # GitLab submodule
   │   └── ...
   ├── source              # bundled (all-in-one) implementation
   │   └── ...
   ├── vendor              # vendors, archives & dependencies
   │   └── ...
   └── ...
