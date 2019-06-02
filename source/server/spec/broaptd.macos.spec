# -*- mode: python -*-
# pylint: disable=all

block_cipher = None


a = Analysis(['../python/__init__.py',
              '../python/__main__.py',
              '../python/cli.py',
              '../python/const.py',
              '../python/daemon.py',
              '../python/process.py',
              '../python/util.py'],
             pathex=['./python/'],
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
          name='broaptd.macos',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=True )
