"""Catalog of officially supported PC games and their process executable names."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SupportedGame:
    """Definition of an officially supported PC game for process sniffing.

    Attributes:
        name: The official display name of the game.
        executable_names: Lowercase executable file names (with extension) representing the game.
        verify_authenticode: Whether Authenticode signature verification is required.
    """

    name: str
    executable_names: tuple[str, ...]
    verify_authenticode: bool = False


SUPPORTED_PC_GAMES: tuple[SupportedGame, ...] = (
    SupportedGame(
        name='Borderlands 2',
        executable_names=('borderlands2.exe',),
    ),
    SupportedGame(
        name='Borderlands 3',
        executable_names=('borderlands3.exe',),
    ),
    SupportedGame(
        name='Borderlands 4',
        executable_names=('borderlands4.exe',),
    ),
    SupportedGame(
        name='Borderlands: The Pre-Sequel',
        executable_names=('borderlandspresequel.exe',),
    ),
    SupportedGame(
        name='Call of Duty®: Advanced Warfare',
        executable_names=('s1_mp64_ship.exe', 's1_sp64_ship.exe'),
    ),
    SupportedGame(
        name='Call of Duty®: Black Ops',
        executable_names=('blackops.exe', 'blackopsmp.exe'),
    ),
    SupportedGame(
        name='Call of Duty®: Black Ops Cold War',
        executable_names=('blackopscoldwar.exe',),
    ),
    SupportedGame(
        name='Call of Duty®: Black Ops II',
        executable_names=('t6mp.exe', 't6zm.exe', 't6sp.exe'),
    ),
    SupportedGame(
        name='Call of Duty®: Black Ops III',
        executable_names=('blackops3.exe',),
    ),
    SupportedGame(
        name='Call of Duty®: Ghosts',
        executable_names=('iw6mp64_ship.exe', 'iw6sp64_ship.exe'),
    ),
    SupportedGame(
        name='Call of Duty®: Infinite Warfare',
        executable_names=('iw7_ship.exe',),
    ),
    SupportedGame(
        name='Call of Duty®: Modern Warfare® 2 (2009)',
        executable_names=('iw4mp.exe', 'iw4sp.exe'),
    ),
    SupportedGame(
        name='Call of Duty®: Modern Warfare® 3 (2011)',
        executable_names=('iw5mp.exe', 'iw5sp.exe'),
    ),
    SupportedGame(
        name='Call of Duty®: Vanguard',
        executable_names=('vanguard.exe',),
    ),
    SupportedGame(
        name='Call of Duty®: WWII',
        executable_names=('s2_mp64_ship.exe', 's2_sp64_ship.exe'),
    ),
    SupportedGame(
        name='Deep Rock Galactic',
        executable_names=('fsd-win64-shipping.exe', 'fsd.exe'),
    ),
    SupportedGame(
        name='DRAGON BALL FighterZ',
        executable_names=('dbfighterz.exe', 'red-win64-shipping.exe'),
    ),
    SupportedGame(
        name='Dying Light',
        executable_names=('dyinglightgame.exe',),
    ),
    SupportedGame(
        name='Dying Light 2',
        executable_names=('dyinglightgame_x64_rwdi.exe',),
    ),
    SupportedGame(
        name='ELDEN RING NIGHTREIGN',
        executable_names=('nightreign.exe', 'eldenring.exe'),
    ),
    SupportedGame(
        name='Generation Zero®',
        executable_names=('generationzero_f.exe',),
    ),
    SupportedGame(
        name='Green Hell',
        executable_names=('gh.exe',),
    ),
    SupportedGame(
        name='Grand Theft Auto Online',
        executable_names=('gta5.exe', 'gta5_enhanced.exe'),
        verify_authenticode=True,
    ),
    SupportedGame(
        name='Minecraft: Bedrock Edition',
        executable_names=('minecraft.windows.exe',),
    ),
    SupportedGame(
        name='Monopoly Madness',
        executable_names=('monopolymadness.exe',),
    ),
    SupportedGame(
        name='Monster Hunter: World',
        executable_names=('monsterhunterworld.exe',),
    ),
    SupportedGame(
        name='Mortal Kombat 11',
        executable_names=('mk11.exe',),
    ),
    SupportedGame(
        name='Mortal Kombat X',
        executable_names=('mk10.exe',),
    ),
    SupportedGame(
        name='NARUTO SHIPPUDEN: Ultimate Ninja STORM Revolution',
        executable_names=('nsunsr.exe',),
    ),
    SupportedGame(
        name='Need for Speed™ Most Wanted',
        executable_names=('nfs13.exe',),
    ),
    SupportedGame(
        name='NEW MONOPOLY®',
        executable_names=('monopoly.exe',),
    ),
    SupportedGame(
        name='Payday 2',
        executable_names=('payday2_win32_release.exe',),
    ),
    SupportedGame(
        name='Ready or Not',
        executable_names=('readyornot-win64-shipping.exe', 'readyornot.exe'),
    ),
    SupportedGame(
        name='Red Dead Online',
        executable_names=('rdr2.exe',),
    ),
    SupportedGame(
        name='Risk of Rain 2',
        executable_names=('risk of rain 2.exe',),
    ),
    SupportedGame(
        name='Sons Of The Forest',
        executable_names=('sonsoftheforest.exe',),
    ),
    SupportedGame(
        name='Street Fighter 30th Anniversary Collection',
        executable_names=('sf30thanniversarycollection.exe',),
    ),
    SupportedGame(
        name='TEKKEN 7',
        executable_names=('tekkengame-win64-shipping.exe', 'tekkengame.exe'),
    ),
    SupportedGame(
        name='The Division 2',
        executable_names=('thedivision2.exe',),
    ),
    SupportedGame(
        name='theHunter Call of the Wild™',
        executable_names=('thehuntercotw_f.exe',),
    ),
    SupportedGame(
        name='theHunter Classic',
        executable_names=('thehunter.exe',),
    ),
    SupportedGame(
        name="Tom Clancy's Ghost Recon® Breakpoint",
        executable_names=('grb.exe',),
    ),
    SupportedGame(
        name="Tom Clancy's Ghost Recon® Wildlands",
        executable_names=('grw.exe',),
    ),
    SupportedGame(
        name='Ultra Street Fighter IV',
        executable_names=('ssfiv.exe',),
    ),
    SupportedGame(
        name='UNO',
        executable_names=('uno.exe',),
    ),
    SupportedGame(
        name='Warframe',
        executable_names=('warframe.x64.exe', 'warframe.exe'),
    ),
    SupportedGame(
        name='Watch Dogs® 2',
        executable_names=('watchdogs2.exe',),
    ),
)

GAME_BY_EXECUTABLE_NAME: dict[str, SupportedGame] = {
    executable_name.lower(): game
    for game in SUPPORTED_PC_GAMES
    for executable_name in game.executable_names
}

ALL_SUPPORTED_EXECUTABLE_NAMES: frozenset[str] = frozenset(GAME_BY_EXECUTABLE_NAME.keys())
