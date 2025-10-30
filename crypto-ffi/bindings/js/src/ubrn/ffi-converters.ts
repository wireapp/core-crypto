/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/
 */
import { UniffiInternalError } from "./errors";
import { type UniffiByteArray, RustBuffer } from "./ffi-types";

// https://github.com/mozilla/uniffi-rs/blob/main/docs/manual/src/internals/lifting_and_lowering.md
export interface FfiConverter<FfiType, TsType> {
  lift(value: FfiType): TsType;
  lower(value: TsType): FfiType;
  read(from: RustBuffer): TsType;
  write(value: TsType, into: RustBuffer): void;
  allocationSize(value: TsType): number;
}

export abstract class FfiConverterPrimitive<T> implements FfiConverter<T, T> {
  lift(value: T): T {
    return value;
  }
  lower(value: T): T {
    return value;
  }
  abstract read(from: RustBuffer): T;
  abstract write(value: T, into: RustBuffer): void;
  abstract allocationSize(value: T): number;
}

export abstract class AbstractFfiConverterByteArray<TsType>
  implements FfiConverter<UniffiByteArray, TsType>
{
  lift(value: UniffiByteArray): TsType {
    const buffer = RustBuffer.fromByteArray(value);
    return this.read(buffer);
  }
  lower(value: TsType): UniffiByteArray {
    const buffer = RustBuffer.withCapacity(this.allocationSize(value));
    this.write(value, buffer);
    return buffer.byteArray;
  }
  abstract read(from: RustBuffer): TsType;
  abstract write(value: TsType, into: RustBuffer): void;
  abstract allocationSize(value: TsType): number;
}

type NumberType = number | bigint;
class FfiConverterNumber<
  T extends NumberType,
> extends FfiConverterPrimitive<T> {
  // These fields should be private, but Typescript doesn't allow
  // that because of the way they are exposed.
  constructor(
    public reader: (view: DataView) => T,
    public writer: (view: DataView, value: T) => void,
    public byteSize: number,
  ) {
    super();
  }
  read(from: RustBuffer): T {
    return from.readWithView(this.byteSize, this.reader);
  }
  write(value: T, into: RustBuffer): void {
    return into.writeWithView(this.byteSize, (view) =>
      this.writer(view, value),
    );
  }
  allocationSize(value: T): number {
    return this.byteSize;
  }
}

const littleEndian = false;

// Ints
export const FfiConverterInt8 = new FfiConverterNumber(
  (view: DataView) => view.getInt8(0),
  (view: DataView, value: number) => view.setInt8(0, value),
  Int8Array.BYTES_PER_ELEMENT,
);
export const FfiConverterInt16 = new FfiConverterNumber(
  (view: DataView) => view.getInt16(0, littleEndian),
  (view: DataView, value: number) => view.setInt16(0, value, littleEndian),
  Int16Array.BYTES_PER_ELEMENT,
);
export const FfiConverterInt32 = new FfiConverterNumber(
  (view: DataView) => view.getInt32(0, littleEndian),
  (view: DataView, value: number) => view.setInt32(0, value, littleEndian),
  Int32Array.BYTES_PER_ELEMENT,
);
export const FfiConverterInt64 = new FfiConverterNumber(
  (view: DataView) => view.getBigInt64(0, littleEndian),
  (view: DataView, value: bigint) => view.setBigInt64(0, value, littleEndian),
  BigInt64Array.BYTES_PER_ELEMENT,
);

// Floats
export const FfiConverterFloat32 = new FfiConverterNumber(
  (view: DataView) => view.getFloat32(0, littleEndian),
  (view: DataView, value: number) => view.setFloat32(0, value, littleEndian),
  Float32Array.BYTES_PER_ELEMENT,
);
export const FfiConverterFloat64 = new FfiConverterNumber(
  (view: DataView) => view.getFloat64(0, littleEndian),
  (view: DataView, value: number) => view.setFloat64(0, value, littleEndian),
  Float64Array.BYTES_PER_ELEMENT,
);

// UInts
export const FfiConverterUInt8 = new FfiConverterNumber(
  (view: DataView) => view.getUint8(0),
  (view: DataView, value: number) => view.setUint8(0, value),
  Uint8Array.BYTES_PER_ELEMENT,
);
export const FfiConverterUInt16 = new FfiConverterNumber(
  (view: DataView) => view.getUint16(0, littleEndian),
  (view: DataView, value: number) => view.setUint16(0, value, littleEndian),
  Uint16Array.BYTES_PER_ELEMENT,
);
export const FfiConverterUInt32 = new FfiConverterNumber(
  (view: DataView) => view.getUint32(0, littleEndian),
  (view: DataView, value: number) => view.setUint32(0, value, littleEndian),
  Uint32Array.BYTES_PER_ELEMENT,
);
export const FfiConverterUInt64 = new FfiConverterNumber(
  (view: DataView) => view.getBigUint64(0, littleEndian),
  (view: DataView, value: bigint) => view.setBigUint64(0, value, littleEndian),
  BigUint64Array.BYTES_PER_ELEMENT,
);

// Bool
export const FfiConverterBool = (() => {
  const byteConverter = FfiConverterInt8;
  class FfiConverterBool implements FfiConverter<number, boolean> {
    lift(value: number): boolean {
      return !!value;
    }
    lower(value: boolean): number {
      return value ? 1 : 0;
    }
    read(from: RustBuffer): boolean {
      return this.lift(byteConverter.read(from));
    }
    write(value: boolean, into: RustBuffer): void {
      byteConverter.write(this.lower(value), into);
    }
    allocationSize(value: boolean): number {
      return byteConverter.allocationSize(0);
    }
  }
  return new FfiConverterBool();
})();

// Duration
//
// There is currently no JS API for duration, so we'll make this just milliseconds.
//
// Later on we'll need to put a Temporal based converter,
// and switch on from a config file.
export type UniffiDuration = number;
export const FfiConverterDuration = (() => {
  const secondsConverter = FfiConverterUInt64;
  const nanosConverter = FfiConverterUInt32;
  const msPerSecBigInt = BigInt("1000");
  const nanosPerMs = 1e6;
  class FFIConverter extends AbstractFfiConverterByteArray<UniffiDuration> {
    read(from: RustBuffer): UniffiDuration {
      const secsBigInt = secondsConverter.read(from);
      const nanos = nanosConverter.read(from);
      const ms = Number(secsBigInt * msPerSecBigInt);
      if (ms === Number.POSITIVE_INFINITY || ms === Number.NEGATIVE_INFINITY) {
        throw new UniffiInternalError.NumberOverflow();
      }
      return ms + nanos / nanosPerMs;
    }
    write(value: UniffiDuration, into: RustBuffer): void {
      const ms = value.valueOf();
      const secsBigInt = BigInt(Math.trunc(ms)) / msPerSecBigInt;
      const remainingNanos = (ms % 1000) * nanosPerMs;
      secondsConverter.write(secsBigInt, into);
      nanosConverter.write(remainingNanos, into);
    }
    allocationSize(_value: UniffiDuration): number {
      return (
        secondsConverter.allocationSize(msPerSecBigInt) +
        nanosConverter.allocationSize(0)
      );
    }
  }
  return new FFIConverter();
})();

// We'll provide native js Date here; later on we'll need to put a Temporal based converter,
// and switch on from a config file.
export type UniffiTimestamp = Date;
export const FfiConverterTimestamp = (() => {
  const secondsConverter = FfiConverterInt64;
  const nanosConverter = FfiConverterUInt32;
  const msPerSecBigInt = BigInt("1000");
  const nanosPerMs = 1e6;
  const msPerSec = 1e3;
  const maxMsFromEpoch = 8.64e15;
  function safeDate(ms: number) {
    if (Math.abs(ms) > 8.64e15) {
      throw new UniffiInternalError.DateTimeOverflow();
    }
    return new Date(ms);
  }

  class FFIConverter extends AbstractFfiConverterByteArray<UniffiTimestamp> {
    read(from: RustBuffer): UniffiTimestamp {
      const secsBigInt = secondsConverter.read(from);
      const nanos = nanosConverter.read(from);
      const ms = Number(secsBigInt * msPerSecBigInt);
      if (ms >= 0) {
        return safeDate(ms + nanos / nanosPerMs);
      } else {
        return safeDate(ms - nanos / nanosPerMs);
      }
    }
    write(value: UniffiTimestamp, into: RustBuffer): void {
      const ms = value.valueOf();
      const secsBigInt = BigInt(Math.trunc(ms / msPerSec));
      const remainingNanos = Math.abs((ms % msPerSec) * nanosPerMs);
      secondsConverter.write(secsBigInt, into);
      nanosConverter.write(remainingNanos, into);
    }
    allocationSize(_value: UniffiTimestamp): number {
      return (
        secondsConverter.allocationSize(msPerSecBigInt) +
        nanosConverter.allocationSize(0)
      );
    }
  }
  return new FFIConverter();
})();

export class FfiConverterOptional<Item> extends AbstractFfiConverterByteArray<
  Item | undefined
> {
  private static flagConverter = FfiConverterBool;
  constructor(private itemConverter: FfiConverter<any, Item>) {
    super();
  }
  read(from: RustBuffer): Item | undefined {
    const flag = FfiConverterOptional.flagConverter.read(from);
    return flag ? this.itemConverter.read(from) : undefined;
  }
  write(value: Item | undefined, into: RustBuffer): void {
    if (value !== undefined) {
      FfiConverterOptional.flagConverter.write(true, into);
      this.itemConverter.write(value!, into);
    } else {
      FfiConverterOptional.flagConverter.write(false, into);
    }
  }
  allocationSize(value: Item | undefined): number {
    let size = FfiConverterOptional.flagConverter.allocationSize(true);
    if (value !== undefined) {
      size += this.itemConverter.allocationSize(value);
    }
    return size;
  }
}

export class FfiConverterArray<Item> extends AbstractFfiConverterByteArray<
  Array<Item>
> {
  private static sizeConverter = FfiConverterInt32;
  constructor(private itemConverter: FfiConverter<any, Item>) {
    super();
  }
  read(from: RustBuffer): Array<Item> {
    const size = FfiConverterArray.sizeConverter.read(from);
    const array = new Array<Item>(size);
    for (let i = 0; i < size; i++) {
      array[i] = this.itemConverter.read(from);
    }
    return array;
  }
  write(array: Array<Item>, into: RustBuffer): void {
    FfiConverterArray.sizeConverter.write(array.length, into);
    for (const item of array) {
      this.itemConverter.write(item, into);
    }
  }
  allocationSize(array: Array<Item>): number {
    let size = FfiConverterArray.sizeConverter.allocationSize(array.length);
    for (const item of array) {
      size += this.itemConverter.allocationSize(item);
    }
    return size;
  }
}

export class FfiConverterMap<K, V> extends AbstractFfiConverterByteArray<
  Map<K, V>
> {
  private static sizeConverter = FfiConverterInt32;
  constructor(
    private keyConverter: FfiConverter<any, K>,
    private valueConverter: FfiConverter<any, V>,
  ) {
    super();
  }
  read(from: RustBuffer): Map<K, V> {
    const size = FfiConverterMap.sizeConverter.read(from);
    const map = new Map();
    for (let i = 0; i < size; i++) {
      map.set(this.keyConverter.read(from), this.valueConverter.read(from));
    }
    return map;
  }
  write(map: Map<K, V>, into: RustBuffer): void {
    FfiConverterMap.sizeConverter.write(map.size, into);
    for (const [k, v] of map.entries()) {
      this.keyConverter.write(k, into);
      this.valueConverter.write(v, into);
    }
  }
  allocationSize(map: Map<K, V>): number {
    let size = FfiConverterMap.sizeConverter.allocationSize(map.size);
    for (const [k, v] of map.entries()) {
      size +=
        this.keyConverter.allocationSize(k) +
        this.valueConverter.allocationSize(v);
    }
    return size;
  }
}

export const FfiConverterArrayBuffer = (() => {
  const lengthConverter = FfiConverterInt32;
  class FFIConverter extends AbstractFfiConverterByteArray<ArrayBuffer> {
    read(from: RustBuffer): ArrayBuffer {
      const length = lengthConverter.read(from);
      return from.readArrayBuffer(length);
    }
    write(value: ArrayBuffer, into: RustBuffer): void {
      const length = value.byteLength;
      lengthConverter.write(length, into);
      into.writeByteArray(new Uint8Array(value));
    }
    allocationSize(value: ArrayBuffer): number {
      return lengthConverter.allocationSize(0) + value.byteLength;
    }
  }
  return new FFIConverter();
})();

type StringConverter = {
  stringToBytes: (s: string) => UniffiByteArray;
  bytesToString: (ab: UniffiByteArray) => string;
  stringByteLength: (s: string) => number;
};
export function uniffiCreateFfiConverterString(
  converter: StringConverter,
): FfiConverter<UniffiByteArray, string> {
  const lengthConverter = FfiConverterInt32;

  class FFIConverter implements FfiConverter<UniffiByteArray, string> {
    lift(value: UniffiByteArray): string {
      return converter.bytesToString(value);
    }
    lower(value: string): UniffiByteArray {
      return converter.stringToBytes(value);
    }
    read(from: RustBuffer): string {
      const length = lengthConverter.read(from);
      // TODO Currently, RustBufferHelper.cpp is pretty dumb,
      // and copies all the bytes in the underlying ArrayBuffer.
      // Making a better shim for Uint8Array would allow us to use
      // readByteArray here, and eliminate a copy.
      const bytes = from.readArrayBuffer(length);
      return converter.bytesToString(new Uint8Array(bytes));
    }
    write(value: string, into: RustBuffer): void {
      // TODO: work on RustBufferHelper.cpp is needed to avoid
      // the extra copy and use writeByteArray.
      const buffer = converter.stringToBytes(value).buffer;
      const numBytes = buffer.byteLength;
      lengthConverter.write(numBytes, into);
      into.writeArrayBuffer(buffer);
    }
    allocationSize(value: string): number {
      return (
        lengthConverter.allocationSize(0) + converter.stringByteLength(value)
      );
    }
  }
  return new FFIConverter();
}
