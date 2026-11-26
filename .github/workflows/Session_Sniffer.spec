# -*- mode: python ; coding: utf-8 -*-

import sys
import tomllib
from pathlib import Path


a = Analysis(
    ['../../src/session_sniffer/launcher/bootstrap.py'],
    pathex=['../../src'],
    binaries=[],
    datas=[
        ('../../pyproject.toml', '.'),
        ('../../resources', 'resources'),
        ('../../scripts', 'scripts'),
        ('../../src/session_sniffer/webserver/static', 'session_sniffer/webserver/static'),
    ],
    hiddenimports=['session_sniffer.main'],
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
        'PySide6.QtLabsStyleKit',
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
        'PySide6.QtQmlFeatures',
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
    # Transitive C++ Qt libraries pulled in only by unused Qt plugins
    # (qpdf, qtuiotouchplugin, qtvirtualkeyboardplugin)
    'qt6pdf.dll',
    'qtpdf',
    'qt6network.dll',
    'qtnetwork',
    'qt6quick.dll',
    'qtquick',
    'qt6qml.dll',
    'qtqml',
    'qt6qmlmeta.dll',
    'qtqmlmeta',
    'qt6qmlmodels.dll',
    'qtqmlmodels',
    'qt6qmlworkerscript.dll',
    'qtqmlworkerscript',
    'qt6virtualkeyboard.dll',
    'qtvirtualkeyboard',
    'qtvirtualkeyboardqml',
    # Unused on Windows/macOS (kept on Linux because Wayland graphics plugins link libQt6OpenGL.so.6)
    'qt6opengl.dll',
    'qtopengl',
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
    'libqmacheif.dylib',
    'libqmacjp2.dylib',
    # Unused Qt generic TUIO touch network plugin and virtual keyboard input context plugin
    'qtuiotouchplugin.dll',
    'libqtuiotouchplugin.so',
    'libqtuiotouchplugin.dylib',
    'qtvirtualkeyboardplugin.dll',
    'libqtvirtualkeyboardplugin.so',
    'libqtvirtualkeyboardplugin.dylib',
    # Unused headless/alternative/embedded platform plugins (qwindows/qxcb/qwayland/qcocoa are kept)
    'qdirect2d.dll',
    'qoffscreen.dll',
    'libqoffscreen.so',
    'libqoffscreen.dylib',
    'qminimal.dll',
    'libqminimal.so',
    'libqminimal.dylib',
    'libqeglfs.so',
    'libqlinuxfb.so',
    'libqminimalegl.so',
    'libqvkkhrdisplay.so',
    'libqvnc.so',
    'libqeglfs-emu-integration.so',
    'libqeglfs-kms-egldevice-integration.so',
    'libqeglfs-x11-integration.so',
}

_EXCLUDED_QT_SO_PREFIXES = (
    'libqt6pdf.so',
    'libqt6network.so',
    'libqt6quick.so',
    'libqt6qml.so',
    'libqt6qmlmeta.so',
    'libqt6qmlmodels.so',
    'libqt6qmlworkerscript.so',
    'libqt6virtualkeyboard.so',
    'libqt6virtualkeyboardqml.so',
    'libqt6eglfsdeviceintegration.so',
    'libqt6eglfskmssupport.so',
)

_EXCLUDED_QT_MACOS_FRAMEWORK_SEGMENTS = (
    '/qtpdf.framework/',
    '/qtnetwork.framework/',
    '/qtquick.framework/',
    '/qtqml.framework/',
    '/qtqmlmeta.framework/',
    '/qtqmlmodels.framework/',
    '/qtqmlworkerscript.framework/',
    '/qtvirtualkeyboard.framework/',
    '/qtvirtualkeyboardqml.framework/',
    '/qtopengl.framework/',
)

_RETAINED_QT_TRANSLATION_FILES = frozenset(
    {
        'qtbase_ar.qm',
        'qtbase_bg.qm',
        'qtbase_ca.qm',
        'qtbase_cs.qm',
        'qtbase_da.qm',
        'qtbase_de.qm',
        'qtbase_es.qm',
        'qtbase_fa.qm',
        'qtbase_fi.qm',
        'qtbase_fr.qm',
        'qtbase_gd.qm',
        'qtbase_he.qm',
        'qtbase_hr.qm',
        'qtbase_hu.qm',
        'qtbase_it.qm',
        'qtbase_ja.qm',
        'qtbase_ka.qm',
        'qtbase_kk.qm',
        'qtbase_ko.qm',
        'qtbase_lg.qm',
        'qtbase_lv.qm',
        'qtbase_nl.qm',
        'qtbase_nn.qm',
        'qtbase_pl.qm',
        'qtbase_pt_br.qm',
        'qtbase_ru.qm',
        'qtbase_sk.qm',
        'qtbase_sv.qm',
        'qtbase_tr.qm',
        'qtbase_uk.qm',
        'qtbase_zh_cn.qm',
        'qtbase_zh_tw.qm',
    },
)


def _is_excluded_qt_framework_entry(normalized_path: str) -> bool:
    rooted_path = f'/{normalized_path.lstrip("/")}'
    return any(segment in rooted_path for segment in _EXCLUDED_QT_MACOS_FRAMEWORK_SEGMENTS)


def _is_excluded_qt_target(normalized_path: str) -> bool:
    basename = normalized_path.rsplit('/', 1)[-1]
    return (
        basename in _EXCLUDED_QT_BINARY_NAMES
        or basename.startswith(_EXCLUDED_QT_SO_PREFIXES)
        or _is_excluded_qt_framework_entry(normalized_path)
    )


def _is_excluded_qt_symlink(entry: tuple[str, ...]) -> bool:
    return len(entry) >= 3 and entry[2] == 'SYMLINK' and _is_excluded_qt_target(entry[1].replace('\\', '/').lower())


a.binaries = [
    binary
    for binary in a.binaries
    if (normalized_dest := binary[0].replace('\\', '/').lower())
    and not _is_excluded_qt_target(normalized_dest)
    and not _is_excluded_qt_symlink(binary)
]
a.datas = [
    data
    for data in a.datas
    if not _is_excluded_qt_framework_entry(normalized_dest := data[0].replace('\\', '/').lower())
    and not _is_excluded_qt_symlink(data)
    and (
        not normalized_dest.startswith(('pyside6/translations/', 'pyside6/qt/translations/'))
        or normalized_dest.rsplit('/', 1)[-1] in _RETAINED_QT_TRANSLATION_FILES
    )
]


def _build_windows_version_info():
    """Build Windows VS_VERSION_INFO PE metadata from pyproject.toml."""
    from packaging.version import Version
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo,
        StringFileInfo,
        StringStruct,
        StringTable,
        VarFileInfo,
        VarStruct,
        VSVersionInfo,
    )

    pyproject_path = Path(SPECPATH) / '..' / '..' / 'pyproject.toml'
    project_data = tomllib.loads(pyproject_path.read_text(encoding='utf-8'))['project']
    raw_version = str(project_data['version'])
    parsed_version = Version(raw_version)

    release_parts = list(parsed_version.release[:3])
    while len(release_parts) < 3:
        release_parts.append(0)
    pre_number = parsed_version.pre[1] if parsed_version.pre is not None else 0
    version_tuple = tuple(min(max(int(part), 0), 65535) for part in (*release_parts, pre_number))
    file_version_str = '.'.join(str(part) for part in version_tuple)

    authors = project_data.get('authors') or []
    author_name = str(authors[0].get('name', 'BUZZARDGTA')) if authors else 'BUZZARDGTA'

    return VSVersionInfo(
        ffi=FixedFileInfo(
            filevers=version_tuple,
            prodvers=version_tuple,
            mask=0x3F,
            flags=0x2 if parsed_version.is_prerelease else 0x0,
            OS=0x40004,
            fileType=0x1,
            subtype=0x0,
            date=(0, 0),
        ),
        kids=[
            StringFileInfo(
                [
                    StringTable(
                        '040904B0',
                        [
                            StringStruct('CompanyName', 'IB_U_Z_Z_A_R_Dl'),
                            StringStruct('FileDescription', 'Session Sniffer'),
                            StringStruct('FileVersion', file_version_str),
                            StringStruct('InternalName', 'Session_Sniffer'),
                            StringStruct('LegalCopyright', f'Copyright (c) {author_name}. Licensed under GPL-3.0.'),
                            StringStruct('OriginalFilename', 'Session_Sniffer.exe'),
                            StringStruct('ProductName', 'Session Sniffer'),
                            StringStruct('ProductVersion', raw_version),
                        ],
                    ),
                ],
            ),
            VarFileInfo([VarStruct('Translation', [1033, 1200])]),
        ],
    )


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
    version=_build_windows_version_info() if sys.platform == 'win32' else None,
)
