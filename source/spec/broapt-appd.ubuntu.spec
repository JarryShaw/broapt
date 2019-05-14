# -*- mode: python -*-
# pylint: disable=all

block_cipher = None


a = Analysis(['../server/__init__.py',
              '../server/__main__.py',
              '../server/cli.py',
              '../server/const.py',
              '../server/daemon.py',
              '../server/process.py',
              '../server/util.py'],
             pathex=['./server/'],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
          cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='broapt-appd.ubuntu',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=True)
