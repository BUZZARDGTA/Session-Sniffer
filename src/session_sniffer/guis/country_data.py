"""Country name and ISO 3166-1 alpha-2 code mappings for the country detection UI."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

COUNTRY_NAMES: dict[str, str] = {
    'AD': 'Andorra',
    'AE': 'United Arab Emirates',
    'AF': 'Afghanistan',
    'AG': 'Antigua and Barbuda',
    'AI': 'Anguilla',
    'AL': 'Albania',
    'AM': 'Armenia',
    'AO': 'Angola',
    'AQ': 'Antarctica',
    'AR': 'Argentina',
    'AS': 'American Samoa',
    'AT': 'Austria',
    'AU': 'Australia',
    'AW': 'Aruba',
    'AX': 'Åland Islands',
    'AZ': 'Azerbaijan',
    'BA': 'Bosnia and Herzegovina',
    'BB': 'Barbados',
    'BD': 'Bangladesh',
    'BE': 'Belgium',
    'BF': 'Burkina Faso',
    'BG': 'Bulgaria',
    'BH': 'Bahrain',
    'BI': 'Burundi',
    'BJ': 'Benin',
    'BL': 'Saint Barthélemy',
    'BM': 'Bermuda',
    'BN': 'Brunei',
    'BO': 'Bolivia',
    'BQ': 'Caribbean Netherlands',
    'BR': 'Brazil',
    'BS': 'Bahamas',
    'BT': 'Bhutan',
    'BV': 'Bouvet Island',
    'BW': 'Botswana',
    'BY': 'Belarus',
    'BZ': 'Belize',
    'CA': 'Canada',
    'CC': 'Cocos (Keeling) Islands',
    'CD': 'DR Congo',
    'CF': 'Central African Republic',
    'CG': 'Republic of the Congo',
    'CH': 'Switzerland',
    'CI': "Côte d'Ivoire",
    'CK': 'Cook Islands',
    'CL': 'Chile',
    'CM': 'Cameroon',
    'CN': 'China',
    'CO': 'Colombia',
    'CR': 'Costa Rica',
    'CU': 'Cuba',
    'CV': 'Cape Verde',
    'CW': 'Curaçao',
    'CX': 'Christmas Island',
    'CY': 'Cyprus',
    'CZ': 'Czechia',
    'DE': 'Germany',
    'DJ': 'Djibouti',
    'DK': 'Denmark',
    'DM': 'Dominica',
    'DO': 'Dominican Republic',
    'DZ': 'Algeria',
    'EC': 'Ecuador',
    'EE': 'Estonia',
    'EG': 'Egypt',
    'EH': 'Western Sahara',
    'ER': 'Eritrea',
    'ES': 'Spain',
    'ET': 'Ethiopia',
    'FI': 'Finland',
    'FJ': 'Fiji',
    'FK': 'Falkland Islands',
    'FM': 'Micronesia',
    'FO': 'Faroe Islands',
    'FR': 'France',
    'GA': 'Gabon',
    'GB': 'United Kingdom',
    'GD': 'Grenada',
    'GE': 'Georgia',
    'GF': 'French Guiana',
    'GG': 'Guernsey',
    'GH': 'Ghana',
    'GI': 'Gibraltar',
    'GL': 'Greenland',
    'GM': 'Gambia',
    'GN': 'Guinea',
    'GP': 'Guadeloupe',
    'GQ': 'Equatorial Guinea',
    'GR': 'Greece',
    'GS': 'South Georgia and the South Sandwich Islands',
    'GT': 'Guatemala',
    'GU': 'Guam',
    'GW': 'Guinea-Bissau',
    'GY': 'Guyana',
    'HK': 'Hong Kong',
    'HM': 'Heard Island and McDonald Islands',
    'HN': 'Honduras',
    'HR': 'Croatia',
    'HT': 'Haiti',
    'HU': 'Hungary',
    'ID': 'Indonesia',
    'IE': 'Ireland',
    'IL': 'Israel',
    'IM': 'Isle of Man',
    'IN': 'India',
    'IO': 'British Indian Ocean Territory',
    'IQ': 'Iraq',
    'IR': 'Iran',
    'IS': 'Iceland',
    'IT': 'Italy',
    'JE': 'Jersey',
    'JM': 'Jamaica',
    'JO': 'Jordan',
    'JP': 'Japan',
    'KE': 'Kenya',
    'KG': 'Kyrgyzstan',
    'KH': 'Cambodia',
    'KI': 'Kiribati',
    'KM': 'Comoros',
    'KN': 'Saint Kitts and Nevis',
    'KP': 'North Korea',
    'KR': 'South Korea',
    'KW': 'Kuwait',
    'KY': 'Cayman Islands',
    'KZ': 'Kazakhstan',
    'LA': 'Laos',
    'LB': 'Lebanon',
    'LC': 'Saint Lucia',
    'LI': 'Liechtenstein',
    'LK': 'Sri Lanka',
    'LR': 'Liberia',
    'LS': 'Lesotho',
    'LT': 'Lithuania',
    'LU': 'Luxembourg',
    'LV': 'Latvia',
    'LY': 'Libya',
    'MA': 'Morocco',
    'MC': 'Monaco',
    'MD': 'Moldova',
    'ME': 'Montenegro',
    'MF': 'Saint Martin',
    'MG': 'Madagascar',
    'MH': 'Marshall Islands',
    'MK': 'North Macedonia',
    'ML': 'Mali',
    'MM': 'Myanmar',
    'MN': 'Mongolia',
    'MO': 'Macau',
    'MP': 'Northern Mariana Islands',
    'MQ': 'Martinique',
    'MR': 'Mauritania',
    'MS': 'Montserrat',
    'MT': 'Malta',
    'MU': 'Mauritius',
    'MV': 'Maldives',
    'MW': 'Malawi',
    'MX': 'Mexico',
    'MY': 'Malaysia',
    'MZ': 'Mozambique',
    'NA': 'Namibia',
    'NC': 'New Caledonia',
    'NE': 'Niger',
    'NF': 'Norfolk Island',
    'NG': 'Nigeria',
    'NI': 'Nicaragua',
    'NL': 'Netherlands',
    'NO': 'Norway',
    'NP': 'Nepal',
    'NR': 'Nauru',
    'NU': 'Niue',
    'NZ': 'New Zealand',
    'OM': 'Oman',
    'PA': 'Panama',
    'PE': 'Peru',
    'PF': 'French Polynesia',
    'PG': 'Papua New Guinea',
    'PH': 'Philippines',
    'PK': 'Pakistan',
    'PL': 'Poland',
    'PM': 'Saint Pierre and Miquelon',
    'PN': 'Pitcairn Islands',
    'PR': 'Puerto Rico',
    'PS': 'Palestine',
    'PT': 'Portugal',
    'PW': 'Palau',
    'PY': 'Paraguay',
    'QA': 'Qatar',
    'RE': 'Réunion',
    'RO': 'Romania',
    'RS': 'Serbia',
    'RU': 'Russia',
    'RW': 'Rwanda',
    'SA': 'Saudi Arabia',
    'SB': 'Solomon Islands',
    'SC': 'Seychelles',
    'SD': 'Sudan',
    'SE': 'Sweden',
    'SG': 'Singapore',
    'SH': 'Saint Helena',
    'SI': 'Slovenia',
    'SJ': 'Svalbard and Jan Mayen',
    'SK': 'Slovakia',
    'SL': 'Sierra Leone',
    'SM': 'San Marino',
    'SN': 'Senegal',
    'SO': 'Somalia',
    'SR': 'Suriname',
    'SS': 'South Sudan',
    'ST': 'São Tomé and Príncipe',
    'SV': 'El Salvador',
    'SX': 'Sint Maarten',
    'SY': 'Syria',
    'SZ': 'Eswatini',
    'TC': 'Turks and Caicos Islands',
    'TD': 'Chad',
    'TF': 'French Southern Territories',
    'TG': 'Togo',
    'TH': 'Thailand',
    'TJ': 'Tajikistan',
    'TK': 'Tokelau',
    'TL': 'Timor-Leste',
    'TM': 'Turkmenistan',
    'TN': 'Tunisia',
    'TO': 'Tonga',
    'TR': 'Turkey',
    'TT': 'Trinidad and Tobago',
    'TV': 'Tuvalu',
    'TW': 'Taiwan',
    'TZ': 'Tanzania',
    'UA': 'Ukraine',
    'UG': 'Uganda',
    'UM': 'United States Minor Outlying Islands',
    'US': 'United States',
    'UY': 'Uruguay',
    'UZ': 'Uzbekistan',
    'VA': 'Vatican City',
    'VC': 'Saint Vincent and the Grenadines',
    'VE': 'Venezuela',
    'VG': 'British Virgin Islands',
    'VI': 'United States Virgin Islands',
    'VN': 'Vietnam',
    'VU': 'Vanuatu',
    'WF': 'Wallis and Futuna',
    'WS': 'Samoa',
    'XK': 'Kosovo',
    'YE': 'Yemen',
    'YT': 'Mayotte',
    'ZA': 'South Africa',
    'ZM': 'Zambia',
    'ZW': 'Zimbabwe',
}

COUNTRY_CODES: dict[str, str] = {country_name: country_code for country_code, country_name in COUNTRY_NAMES.items()}

# Alternative English country names returned by GeoLite2-Country.mmdb that differ from COUNTRY_NAMES.
_GEOLITE2_COUNTRY_ALIASES: dict[str, str] = {
    'Bonaire, Sint Eustatius and Saba': 'BQ',
    'Congo (DRC)': 'CD',
    'Congo Republic': 'CG',
    'Ivory Coast': 'CI',
    'Cabo Verde': 'CV',
    'Federated States of Micronesia': 'FM',
    'Heard and McDonald Islands': 'HM',
    'Macao': 'MO',
    'The Netherlands': 'NL',
    'St. Helena': 'SH',
    'Türkiye': 'TR',
    'U.S. Virgin Islands': 'VI',
}

_COUNTRY_CODES_CASEFOLDED: dict[str, str] = {
    **{country_name.casefold(): country_code for country_code, country_name in COUNTRY_NAMES.items()},
    **{alias.casefold(): country_code for alias, country_code in _GEOLITE2_COUNTRY_ALIASES.items()},
}


def _resolve_geo_code(
    raw_value: str,
    names_by_code: dict[str, str],
    codes_by_name: dict[str, str],
    codes_casefolded: dict[str, str],
) -> str | None:
    """Resolve a geographic display name, alias, `'CODE - Name'`, `'Name (CODE)'`, or 2-letter code."""
    stripped = raw_value.strip()
    if not stripped:
        return None
    upper = stripped.upper()
    if upper in names_by_code:
        return upper
    code = codes_by_name.get(raw_value) or codes_casefolded.get(stripped.casefold())
    if code is not None:
        return code
    if ' - ' in stripped:
        prefix, _, suffix = stripped.partition(' - ')
        prefix_upper = prefix.strip().upper()
        if prefix_upper in names_by_code and codes_casefolded.get(suffix.strip().casefold()) == prefix_upper:
            return prefix_upper
    if stripped.endswith(')') and ' (' in stripped:
        prefix, _, suffix = stripped[:-1].rpartition(' (')
        suffix_upper = suffix.strip().upper()
        if suffix_upper in names_by_code and codes_casefolded.get(prefix.strip().casefold()) == suffix_upper:
            return suffix_upper
    return None


def _matches_geo_target(target: str, candidates: tuple[object, ...], resolve_code: Callable[[str], str | None]) -> bool:
    """Return True if any lookup candidate string matches *target* by canonical code or casefolded name."""
    target_stripped = target.strip()
    if not target_stripped:
        return False
    target_code = resolve_code(target_stripped)
    target_folded = target_stripped.casefold()
    for candidate in candidates:
        if not isinstance(candidate, str) or candidate in ('', '...', 'N/A'):
            continue
        if target_code is not None and resolve_code(candidate) == target_code:
            return True
        if candidate.strip().casefold() == target_folded:
            return True
    return False


def get_country_flag_code(country_name: str) -> str | None:
    """Return the 2-letter flag file code for a country name, alias, or ISO code, or None if unknown."""
    return _resolve_geo_code(country_name, COUNTRY_NAMES, COUNTRY_CODES, _COUNTRY_CODES_CASEFOLDED)


def normalize_country_name(country_name: str) -> str | None:
    """Resolve a country name, GeoLite2 alias, or ISO code to its canonical COUNTRY_NAMES display name."""
    code = get_country_flag_code(country_name)
    return COUNTRY_NAMES.get(code) if code is not None else None


def matches_country(target: str, *candidates: object) -> bool:
    """Return True if any lookup candidate (country name or ISO code) matches *target*."""
    return _matches_geo_target(target, candidates, get_country_flag_code)


CONTINENT_NAMES: dict[str, str] = {
    'AF': 'Africa',
    'AN': 'Antarctica',
    'AS': 'Asia',
    'EU': 'Europe',
    'NA': 'North America',
    'OC': 'Oceania',
    'SA': 'South America',
}

CONTINENT_CODES: dict[str, str] = {continent_name: continent_code for continent_code, continent_name in CONTINENT_NAMES.items()}

_CONTINENT_CODES_CASEFOLDED: dict[str, str] = {continent_name.casefold(): continent_code for continent_code, continent_name in CONTINENT_NAMES.items()}


def get_continent_code(continent_name: str) -> str | None:
    """Return the 2-letter continent code for a continent name or code, or None if unknown."""
    return _resolve_geo_code(continent_name, CONTINENT_NAMES, CONTINENT_CODES, _CONTINENT_CODES_CASEFOLDED)


def normalize_continent_name(continent_name: str) -> str | None:
    """Resolve a continent name or 2-letter code to its canonical CONTINENT_NAMES display name."""
    code = get_continent_code(continent_name)
    return CONTINENT_NAMES.get(code) if code is not None else None


def matches_continent(target: str, *candidates: object) -> bool:
    """Return True if any lookup candidate (continent name or 2-letter code) matches *target*."""
    return _matches_geo_target(target, candidates, get_continent_code)
