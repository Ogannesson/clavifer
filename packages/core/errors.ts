export class Fault extends Error {
  constructor(
    public code: string,
    public status = 400,
    message = code,
  ) {
    super(message);
  }
}
// A message other than the code is a next-step hint that error responses pass on to the caller.
export function assert(condition: unknown, code: string, status = 400, message = code): asserts condition {
  if (!condition) throw new Fault(code, status, message);
}
