"""Run from the repository root; see GENERATION.md."""
from pathlib import Path
import struct

import pyarrow as pa
import pyarrow.parquet as pq

assert pa.__version__ == "25.0.1", pa.__version__
root = Path(__file__).resolve().parent
arrays = {
    "list": pa.array([[1, 2], None, []], type=pa.list_(pa.int32())),
    "fixed_size_list": pa.array([[1.0, 2.0], None], type=pa.list_(pa.float32(), 2)),
    "nullable_struct": pa.array([{"value": 1}, None, {"value": None}],
                                type=pa.struct([pa.field("value", pa.int32(), nullable=True)])),
    "zero_row_list": pa.array([], type=pa.list_(pa.int32())),
    "drop_list": pa.array([[1], None], type=pa.list_(pa.int32())),
}
for name, array in arrays.items():
    pq.write_table(pa.table({"nested": array}), root / f"{name}.parquet",
                   compression="NONE", use_dictionary=False)

# Preserve the leading magic, footer metadata and trailing footer length/magic.
raw = bytearray((root / "list.parquet").read_bytes())
footer_start = len(raw) - 8 - struct.unpack("<I", raw[-8:-4])[0]
assert footer_start > 4 and raw[:4] == raw[-4:] == b"PAR1"
raw[4:footer_start] = b"\xff" * (footer_start - 4)
corrupt = root / "corrupt_pages_list.parquet"
corrupt.write_bytes(raw)
assert pq.ParquetFile(corrupt).schema.column(0).max_repetition_level == 1
try:
    pq.read_table(corrupt)
except (pa.ArrowInvalid, OSError):
    pass
else:
    raise AssertionError("corrupt data pages unexpectedly readable")
