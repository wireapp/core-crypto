export function safeBigintToNumber(x: bigint): number {
    if (
        x > BigInt(Number.MAX_SAFE_INTEGER) ||
        x < BigInt(Number.MIN_SAFE_INTEGER)
    ) {
        throw new Error(
            `"${x}" is too large to be safely contained in a JS number`
        );
    }
    return new Number(x).valueOf();
}
