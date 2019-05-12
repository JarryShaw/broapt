# -*- mode: python -*-
# pylint: disable=all

block_cipher = None


a = Analysis(['../source/python/__init__.py', '../source/python/__main__.py', '../source/python/cfgparser.py'],
             pathex=['./source/python/'],
             binaries=[('/usr/lib64/libyaml-0.so.2', 'libyaml.so')],
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
          name='broapt-app.centos',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=True)
