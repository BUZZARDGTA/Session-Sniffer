# -*- mode: python ; coding: utf-8 -*-

import sys


a = Analysis(
    ['../../src/session_sniffer/main.py'],
    pathex=['../../src'],
    binaries=[],
    datas=[
        ('../../pyproject.toml', '.'),
        ('../../resources', 'resources'),
        ('../../scripts', 'scripts'),
        ('../../src/session_sniffer/webserver/static', 'session_sniffer/webserver/static'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # PySide6: Keep only the Qt modules strictly required by Session Sniffer:
        # QtCore, QtGui, QtWidgets, and QtSvg (for QSvgRenderer).
        # Exclude all unused Qt modules and associated plugins/DLLs to minimize
        # bundle size and eliminate dead-weight dependencies.
        'PySide6.Qt3DAnimation',
        'PySide6.Qt3DCore',
        'PySide6.Qt3DExtras',
        'PySide6.Qt3DInput',
        'PySide6.Qt3DLogic',
        'PySide6.Qt3DRender',
        'PySide6.QtAsyncio',
        'PySide6.QtAxContainer',
        'PySide6.QtBluetooth',
        'PySide6.QtCanvasPainter',
        'PySide6.QtCharts',
        'PySide6.QtConcurrent',
        'PySide6.QtDBus',
        'PySide6.QtDataVisualization',
        'PySide6.QtDesigner',
        'PySide6.QtGraphs',
        'PySide6.QtGraphsWidgets',
        'PySide6.QtHelp',
        'PySide6.QtHttpServer',
        'PySide6.QtLocation',
        'PySide6.QtMultimedia',
        'PySide6.QtMultimediaWidgets',
        'PySide6.QtNetwork',
        'PySide6.QtNetworkAuth',
        'PySide6.QtNfc',
        'PySide6.QtOpenGL',
        'PySide6.QtOpenGLWidgets',
        'PySide6.QtPdf',
        'PySide6.QtPdfWidgets',
        'PySide6.QtPositioning',
        'PySide6.QtPrintSupport',
        'PySide6.QtQml',
        'PySide6.QtQmlCore',
        'PySide6.QtQmlLocalStorage',
        'PySide6.QtQmlModels',
        'PySide6.QtQmlWorkerScript',
        'PySide6.QtQuick',
        'PySide6.QtQuick3D',
        'PySide6.QtQuickControls2',
        'PySide6.QtQuickTest',
        'PySide6.QtQuickWidgets',
        'PySide6.QtRemoteObjects',
        'PySide6.QtScxml',
        'PySide6.QtSensors',
        'PySide6.QtSerialBus',
        'PySide6.QtSerialPort',
        'PySide6.QtSpatialAudio',
        'PySide6.QtSql',
        'PySide6.QtStateMachine',
        'PySide6.QtSvgWidgets',
        'PySide6.QtTest',
        'PySide6.QtTextToSpeech',
        'PySide6.QtUiTools',
        'PySide6.QtVirtualKeyboard',
        'PySide6.QtWebChannel',
        'PySide6.QtWebEngineCore',
        'PySide6.QtWebEngineQuick',
        'PySide6.QtWebEngineWidgets',
        'PySide6.QtWebSockets',
        'PySide6.QtWebView',
        'PySide6.QtXml',

        # Alternative Qt bindings (prevent accidental collection)
        'PyQt5',
        'PyQt6',

        # Python Standard Library: unused modules, test runners, debuggers, profilers, and GUI toolkits
        'tkinter',
        '_tkinter',
        'turtle',
        'idlelib',
        'unittest',
        'test',
        'doctest',
        'pydoc',
        'pydoc_data',
        'sqlite3',
        '_sqlite3',
        'pdb',
        'cProfile',
        'profile',
        'pstats',
        'curses',
        'xmlrpc',
    ],
    noarchive=False,
    optimize=0,
)

# Strip unused C++ Qt shared libraries, plugins, and localization files that
# PyInstaller's PySide6 hooks collect automatically despite module `excludes`.
_EXCLUDED_QT_BINARY_NAMES = {
    # Software OpenGL Mesa rasterizer (~19.7 MB on Windows); unused by 2D QWidget/QPainter UI
    'opengl32sw.dll',
    # Transitive C++ Qt libraries pulled in only by unused Qt plugins (qpdf, qtuiotouchplugin)
    'qt6pdf.dll',
    'qtpdf',
    'qt6network.dll',
    'qtnetwork',
    # Unused Qt imageformat plugins (Session Sniffer only uses PNG, SVG, and ICO/ICNS)
    'qpdf.dll',
    'libqpdf.so',
    'libqpdf.dylib',
    'qtiff.dll',
    'libqtiff.so',
    'libqtiff.dylib',
    'qjpeg.dll',
    'libqjpeg.so',
    'libqjpeg.dylib',
    'qwebp.dll',
    'libqwebp.so',
    'libqwebp.dylib',
    'qgif.dll',
    'libqgif.so',
    'libqgif.dylib',
    'qtga.dll',
    'libqtga.so',
    'libqtga.dylib',
    'qwbmp.dll',
    'libqwbmp.so',
    'libqwbmp.dylib',
    # Unused Qt generic TUIO touch network plugin
    'qtuiotouchplugin.dll',
    'libqtuiotouchplugin.so',
    'libqtuiotouchplugin.dylib',
    # Unused headless/alternative platform plugins (qwindows/qxcb/qwayland/qcocoa are kept)
    'qdirect2d.dll',
    'qoffscreen.dll',
    'libqoffscreen.so',
    'libqoffscreen.dylib',
    'qminimal.dll',
    'libqminimal.so',
    'libqminimal.dylib',
}

a.binaries = [
    binary
    for binary in a.binaries
    if (basename := binary[0].replace('\\', '/').rsplit('/', 1)[-1].lower()) not in _EXCLUDED_QT_BINARY_NAMES
    and not basename.startswith(('libqt6pdf.so', 'libqt6network.so'))
]
a.datas = [
    data
    for data in a.datas
    if not data[0].replace('\\', '/').lower().startswith(('pyside6/translations/', 'pyside6/qt/translations/'))
]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Session_Sniffer_macOS' if sys.platform == 'darwin' else 'Session_Sniffer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    onefile=True,
    icon='../../resources/icons/ico/app_icon.ico' if sys.platform == 'win32' else None,
)
