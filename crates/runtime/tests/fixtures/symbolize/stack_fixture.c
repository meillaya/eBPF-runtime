/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Golden symbolization fixture for `crates/runtime/src/symbolize.rs`.
 *
 * The checked-in `libstack_fixture.so` is compiled from this file with:
 *
 *     clang-19 -g -O0 -fno-omit-frame-pointer -shared -fPIC \
 *       -o libstack_fixture.so stack_fixture.c
 *
 * The test asserts that blazesym maps the freshly recorded `st_value`
 * virtual offsets in `golden.json` back to these exact function names,
 * source file, and line numbers. Regenerate both the .so and the JSON
 * (`readelf -sW libstack_fixture.so`) if this file changes; the fixture
 * is intentionally frozen so the test never depends on the build host's
 * compiler or on a live process.
 */

int fleet_symbolize_fixture_add(int a, int b)
{
	return a + b;
}

int fleet_symbolize_fixture_scale(int value)
{
	int scaled = value * 3;
	return scaled + 1;
}

int fleet_symbolize_fixture_chain(int value)
{
	return fleet_symbolize_fixture_scale(fleet_symbolize_fixture_add(value, 2));
}
