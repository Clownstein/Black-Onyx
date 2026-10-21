import { describe, expect, it } from "vitest";
import { serializeCsv } from "./csv";

describe("serializeCsv", () => {
  it("quotes fields and preserves commas, quotes, and newlines", () => {
    expect(serializeCsv([{ a: 'alpha,"beta"\ngamma', b: 2 }], ["a", "b"]))
      .toBe('"a","b"\r\n"alpha,""beta""\ngamma","2"');
  });

  it("neutralizes spreadsheet formulas in string cells", () => {
    expect(serializeCsv([{ value: "  =1+1" }, { value: "-1" }], ["value"]))
      .toBe('"value"\r\n"\'  =1+1"\r\n"\'-1"');
  });
});
