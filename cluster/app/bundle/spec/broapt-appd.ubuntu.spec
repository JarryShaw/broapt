# -*- mode: python -*-
# pylint: disable=all

block_cipher = None


a = Analysis(['../../source/server/__init__.py',
              '../../source/server/__main__.py',
              '../../source/server/cli.py',
              '../../source/server/const.py',
              '../../source/server/daemon.py',
              '../../source/server/process.py',
              '../../source/server/util.py'],
             pathex=['./source/server/'],
             binaries=[],
             datas=[],
             hiddenimports=['python-dotenv'],
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
