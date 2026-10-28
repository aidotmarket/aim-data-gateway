These synthetic fixtures require Python with pyarrow 25.0.1, pinned to the
version recorded in `verification/testdata/oracle/GENERATION.md`. No Go
dependencies are needed. From the repository root:

```sh
python3 -m venv /var/tmp/s1837-pyarrow-venv
/var/tmp/s1837-pyarrow-venv/bin/python -m pip install pyarrow==25.0.1
/var/tmp/s1837-pyarrow-venv/bin/python internal/profile/testdata/nested/generate.py
```

The generator records list, fixed-size-list, nullable scalar struct, empty list,
and drop-rule list schemas. `drop_list.parquet` is tested with `nested` dropped.
The corrupt-pages fixture overwrites every byte between the leading `PAR1`
and the footer, retaining valid footer/schema metadata. The generator confirms
that footer inspection succeeds and reading data fails. Its opaque description
documents the accepted limit: nested data pages are not validated.
