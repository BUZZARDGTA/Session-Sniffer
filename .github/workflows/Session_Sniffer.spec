# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['..\\..\\src\\session_sniffer\\main.py'],
    pathex=['..\\..\\src'],
    binaries=[],
    datas=[
        ('..\\..\\pyproject.toml', '.'),
        ('..\\..\\bin', 'bin'),
        ('..\\..\\images', 'images'),
        ('..\\..\\resources', 'resources'),
        ('..\\..\\scripts', 'scripts'),
        ('..\\..\\TTS', 'TTS')
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Session_Sniffer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    onefile=True,
)
