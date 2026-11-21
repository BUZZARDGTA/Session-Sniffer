"""Pure-Python ISO/IEC 18004 QR code encoder (Versions 1-6, EC Level M) and Qt pixmap renderer."""

from typing import TYPE_CHECKING, Final

from PySide6.QtGui import QColor, QPainter, QPixmap

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

# ISO/IEC 18004 Table 9 specs for Versions 1-6 at Error Correction Level M.
# Each tuple holds: version, data_codewords, ec_codewords_per_block, num_blocks, alignment_center.
_VERSION_SPECS: Final[tuple[tuple[int, int, int, int, int | None], ...]] = (
    (1, 16, 10, 1, None),
    (2, 28, 16, 1, 18),
    (3, 44, 26, 1, 22),
    (4, 64, 18, 2, 26),
    (5, 86, 24, 2, 30),
    (6, 108, 16, 4, 34),
)

_GF_PRIMITIVE_POLY: Final[int] = 0x11D
_FORMAT_BCH_POLY: Final[int] = 0x537
_FORMAT_XOR_MASK: Final[int] = 0x5412
_EC_LEVEL_M_BITS: Final[int] = 0b00
_BYTE_MODE_BITS: Final[int] = 0b0100
_PAD_BYTES: Final[tuple[int, int]] = (0xEC, 0x11)
_QUIET_ZONE_MODULES: Final[int] = 4
_FINDER_SIZE: Final[int] = 7
_FINDER_CORE_MIN: Final[int] = 2
_FINDER_CORE_MAX: Final[int] = 4
_TIMING_INDEX: Final[int] = 6
_PENALTY_RUN_MIN: Final[int] = 5
_PENALTY_FINDER_PATTERN_A: Final[tuple[bool, ...]] = (True, False, True, True, True, False, True, False, False, False, False)
_PENALTY_FINDER_PATTERN_B: Final[tuple[bool, ...]] = (False, False, False, False, True, False, True, True, True, False, True)
_MASK_PREDICATES: Final[tuple[Callable[[int, int], bool], ...]] = (
    lambda r, c: not (r + c) % 2,
    lambda r, _c: not r % 2,
    lambda _r, c: not c % 3,
    lambda r, c: not (r + c) % 3,
    lambda r, c: not (r // 2 + c // 3) % 2,
    lambda r, c: not (r * c % 2 + r * c % 3),
    lambda r, c: not (r * c % 2 + r * c % 3) % 2,
    lambda r, c: not ((r + c) % 2 + r * c % 3) % 2,
)


def _gf_mul(lhs: int, rhs: int) -> int:
    """Multiply two elements in GF(2^8) modulo `x^8 + x^4 + x^3 + x^2 + 1`."""
    result = 0
    a = lhs
    b = rhs
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= _GF_PRIMITIVE_POLY
        b >>= 1
    return result


def _rs_generator_poly(ec_len: int) -> list[int]:
    """Compute the Reed-Solomon generator polynomial of degree *ec_len*."""
    poly = [1]
    root = 1
    for _ in range(ec_len):
        next_poly = [0] * (len(poly) + 1)
        for idx, coeff in enumerate(poly):
            next_poly[idx] ^= coeff
            next_poly[idx + 1] ^= _gf_mul(coeff, root)
        poly = next_poly
        root = _gf_mul(root, 2)
    return poly


def _rs_remainder(data: Sequence[int], ec_len: int) -> list[int]:
    """Return the *ec_len* Reed-Solomon error-correction codewords for *data*."""
    generator = _rs_generator_poly(ec_len)
    remainder: list[int] = [0] * ec_len
    for byte in data:
        factor = byte ^ remainder.pop(0)
        remainder.append(0)
        if factor:
            for idx in range(ec_len):
                remainder[idx] ^= _gf_mul(generator[idx + 1], factor)
    return remainder


def _append_bits(target: list[int], value: int, bit_count: int) -> None:
    """Append the lowest *bit_count* bits of *value* (MSB first) to *target*."""
    target.extend((value >> shift) & 1 for shift in range(bit_count - 1, -1, -1))


def _encode_data_codewords(payload: bytes, data_codewords: int) -> list[int]:
    """Encode *payload* in QR byte mode and pad to *data_codewords* bytes."""
    bits: list[int] = []
    _append_bits(bits, _BYTE_MODE_BITS, 4)
    _append_bits(bits, len(payload), 8)
    for byte in payload:
        _append_bits(bits, byte, 8)

    capacity_bits = data_codewords * 8
    terminator_len = min(4, capacity_bits - len(bits))
    bits.extend([0] * terminator_len)
    if remainder := len(bits) % 8:
        bits.extend([0] * (8 - remainder))

    codewords = [
        sum(bits[offset + bit_idx] << (7 - bit_idx) for bit_idx in range(8))
        for offset in range(0, len(bits), 8)
    ]
    pad_idx = 0
    while len(codewords) < data_codewords:
        codewords.append(_PAD_BYTES[pad_idx & 1])
        pad_idx += 1
    return codewords


def _interleave_blocks(codewords: list[int], ec_per_block: int, num_blocks: int) -> list[int]:
    """Split *codewords* into *num_blocks* equal blocks, compute RS parity, and interleave into final bits."""
    block_size = len(codewords) // num_blocks
    data_blocks = [codewords[i * block_size : (i + 1) * block_size] for i in range(num_blocks)]
    ec_blocks = [_rs_remainder(block, ec_per_block) for block in data_blocks]

    interleaved: list[int] = []
    for byte_idx in range(block_size):
        interleaved.extend(block[byte_idx] for block in data_blocks)
    for byte_idx in range(ec_per_block):
        interleaved.extend(block[byte_idx] for block in ec_blocks)

    bits: list[int] = []
    for byte in interleaved:
        _append_bits(bits, byte, 8)
    return bits


def _place_finder_pattern(matrix: list[list[bool]], is_function: list[list[bool]], top: int, left: int) -> None:
    """Place a 7x7 finder pattern and its 1-module white separator at `(top, left)`."""
    size = len(matrix)
    for dr in range(-1, _FINDER_SIZE + 1):
        row = top + dr
        if not 0 <= row < size:
            continue
        for dc in range(-1, _FINDER_SIZE + 1):
            col = left + dc
            if not 0 <= col < size:
                continue
            in_outer = 0 <= dr < _FINDER_SIZE and 0 <= dc < _FINDER_SIZE
            in_core = _FINDER_CORE_MIN <= dr <= _FINDER_CORE_MAX and _FINDER_CORE_MIN <= dc <= _FINDER_CORE_MAX
            dark = in_outer and (dr in (0, _FINDER_SIZE - 1) or dc in (0, _FINDER_SIZE - 1) or in_core)
            matrix[row][col] = dark
            is_function[row][col] = True


def _place_alignment_pattern(matrix: list[list[bool]], is_function: list[list[bool]], center: int) -> None:
    """Place a 5x5 alignment pattern centered at `(center, center)`."""
    for dr in range(-2, 3):
        for dc in range(-2, 3):
            dark = max(abs(dr), abs(dc)) != 1
            matrix[center + dr][center + dc] = dark
            is_function[center + dr][center + dc] = True


def _format_info_bits(mask: int) -> int:
    """Compute the 15-bit BCH-encoded format information word for EC Level M and *mask*."""
    data = (_EC_LEVEL_M_BITS << 3) | mask
    rem = data << 10
    for bit_pos in range(14, 9, -1):
        if rem & (1 << bit_pos):
            rem ^= _FORMAT_BCH_POLY << (bit_pos - 10)
    return ((data << 10) | rem) ^ _FORMAT_XOR_MASK


def _write_format_info(matrix: list[list[bool]], is_function: list[list[bool]], mask: int) -> None:
    """Write the 15-bit format information into both standard QR format strips."""
    size = len(matrix)
    bits = _format_info_bits(mask)

    copy1_coords: tuple[tuple[int, int], ...] = (
        (8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
        (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8),
    )
    copy2_coords: tuple[tuple[int, int], ...] = (
        (size - 1, 8), (size - 2, 8), (size - 3, 8), (size - 4, 8), (size - 5, 8), (size - 6, 8), (size - 7, 8),
        (8, size - 8), (8, size - 7), (8, size - 6), (8, size - 5), (8, size - 4), (8, size - 3), (8, size - 2), (8, size - 1),
    )

    for idx in range(15):
        dark = bool((bits >> (14 - idx)) & 1)
        r1, c1 = copy1_coords[idx]
        r2, c2 = copy2_coords[idx]
        matrix[r1][c1] = dark
        is_function[r1][c1] = True
        matrix[r2][c2] = dark
        is_function[r2][c2] = True


def _mask_predicate(mask: int, row: int, col: int) -> bool:
    """Evaluate ISO/IEC 18004 mask condition *mask* (0-7) at `(row, col)`."""
    return _MASK_PREDICATES[mask](row, col)


def _score_line_runs_and_finder(line: Sequence[bool]) -> int:
    """Compute ISO N1 (consecutive runs) and N3 (finder-like 1:1:3:1:1 patterns) penalties for one row or column."""
    penalty = 0
    run_len = 1
    for idx in range(1, len(line)):
        if line[idx] == line[idx - 1]:
            run_len += 1
        else:
            if run_len >= _PENALTY_RUN_MIN:
                penalty += 3 + (run_len - _PENALTY_RUN_MIN)
            run_len = 1
    if run_len >= _PENALTY_RUN_MIN:
        penalty += 3 + (run_len - _PENALTY_RUN_MIN)

    window_len = len(_PENALTY_FINDER_PATTERN_A)
    for start in range(len(line) - window_len + 1):
        segment = tuple(line[start : start + window_len])
        if segment in (_PENALTY_FINDER_PATTERN_A, _PENALTY_FINDER_PATTERN_B):
            penalty += 40
    return penalty


def _compute_penalty(matrix: list[list[bool]]) -> int:
    """Compute the standard ISO/IEC 18004 mask penalty score (N1 + N2 + N3 + N4)."""
    size = len(matrix)
    penalty = 0
    for row_cells in matrix:
        penalty += _score_line_runs_and_finder(row_cells)
    for col_idx in range(size):
        penalty += _score_line_runs_and_finder([matrix[row_idx][col_idx] for row_idx in range(size)])

    for row_idx in range(size - 1):
        for col_idx in range(size - 1):
            val = matrix[row_idx][col_idx]
            if val == matrix[row_idx][col_idx + 1] == matrix[row_idx + 1][col_idx] == matrix[row_idx + 1][col_idx + 1]:
                penalty += 3

    dark_count = sum(1 for row_cells in matrix for cell in row_cells if cell)
    total_cells = size * size
    deviation = abs(dark_count * 20 - total_cells * 10) // total_cells
    penalty += deviation * 10
    return penalty


def encode_qr_matrix(text: str) -> tuple[tuple[bool, ...], ...] | None:
    """Encode *text* as a QR code boolean matrix (`True` = dark module), or `None` if unsupported."""
    payload = text.encode('utf-8')
    spec = next((entry for entry in _VERSION_SPECS if len(payload) <= entry[1] - 2), None)
    if spec is None:
        return None

    version, data_codewords, ec_per_block, num_blocks, alignment_center = spec
    size = 17 + 4 * version
    base_matrix = [[False] * size for _ in range(size)]
    is_function = [[False] * size for _ in range(size)]

    _place_finder_pattern(base_matrix, is_function, 0, 0)
    _place_finder_pattern(base_matrix, is_function, 0, size - _FINDER_SIZE)
    _place_finder_pattern(base_matrix, is_function, size - _FINDER_SIZE, 0)

    for idx in range(8, size - 8):
        dark = not idx % 2
        base_matrix[_TIMING_INDEX][idx] = dark
        is_function[_TIMING_INDEX][idx] = True
        base_matrix[idx][_TIMING_INDEX] = dark
        is_function[idx][_TIMING_INDEX] = True

    if alignment_center is not None:
        _place_alignment_pattern(base_matrix, is_function, alignment_center)

    base_matrix[size - 8][8] = True
    is_function[size - 8][8] = True
    _write_format_info(base_matrix, is_function, mask=0)

    codewords = _encode_data_codewords(payload, data_codewords)
    data_bits = _interleave_blocks(codewords, ec_per_block, num_blocks)

    bit_idx = 0
    col = size - 1
    upward = True
    while col > 0:
        if col == _TIMING_INDEX:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for dx in (0, 1):
                c = col - dx
                if not is_function[row][c]:
                    base_matrix[row][c] = bool(data_bits[bit_idx]) if bit_idx < len(data_bits) else False
                    bit_idx += 1
        upward = not upward
        col -= 2

    best_matrix: list[list[bool]] | None = None
    best_penalty: int | None = None
    for mask in range(8):
        candidate = [
            [
                base_matrix[row][col] ^ (not is_function[row][col] and _mask_predicate(mask, row, col))
                for col in range(size)
            ]
            for row in range(size)
        ]
        _write_format_info(candidate, is_function, mask=mask)
        penalty = _compute_penalty(candidate)
        if best_penalty is None or penalty < best_penalty:
            best_penalty = penalty
            best_matrix = candidate

    if best_matrix is None:
        return None
    return tuple(tuple(row) for row in best_matrix)


def render_qr_pixmap(text: str, size_px: int) -> QPixmap | None:
    """Render *text* as a crisp white-backed QR code `QPixmap` of *size_px* x *size_px* pixels."""
    matrix = encode_qr_matrix(text)
    if matrix is None:
        return None

    matrix_size = len(matrix)
    total_modules = matrix_size + 2 * _QUIET_ZONE_MODULES
    module_px = max(1, size_px // total_modules)
    drawn_px = total_modules * module_px
    canvas_px = max(size_px, drawn_px)
    offset_px = (canvas_px - drawn_px) // 2

    pixmap = QPixmap(canvas_px, canvas_px)
    pixmap.fill(QColor('#ffffff'))
    painter = QPainter(pixmap)
    try:
        painter.setPen(QColor('#000000'))
        painter.setBrush(QColor('#000000'))
        dark_color = QColor('#000000')
        for row_idx, row in enumerate(matrix):
            y = offset_px + (_QUIET_ZONE_MODULES + row_idx) * module_px
            for col_idx, is_dark in enumerate(row):
                if is_dark:
                    x = offset_px + (_QUIET_ZONE_MODULES + col_idx) * module_px
                    painter.fillRect(x, y, module_px, module_px, dark_color)
    finally:
        painter.end()
    return pixmap
