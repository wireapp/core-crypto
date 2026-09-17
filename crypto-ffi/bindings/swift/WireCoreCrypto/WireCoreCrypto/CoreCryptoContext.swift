import Foundation
import WireCoreCryptoUniffi

/// Defines the protocol for a transaction context.
public protocol CoreCryptoContextProtocol: CoreCryptoContextFfiProtocol {
    @available(*, deprecated, message: "Use proteusNewPrekeyAuto() instead.")
    func proteusNewPrekey(prekeyId: UInt16) async throws -> Data
}

/// A high-level wrapper around a transaction context as emitted by UniFFI.
public final class CoreCryptoContext: CoreCryptoContextProtocol, @unchecked Sendable {
    let coreCryptoContextFfi: CoreCryptoContextFfi

    init(_ context: CoreCryptoContextFfi) {
        self.coreCryptoContextFfi = context
    }

    /// Creates a new Proteus prekey with the given ID and returns its CBOR-serialized bundle.
    ///
    /// Fails if the ID is already in use. Prekeys are not replaceable: the ID has been published to
    /// peers in a bundle, and overwriting it would strand anyone still holding that bundle. Use
    /// `proteusNewPrekeyAuto` to have a free ID chosen instead.
    ///
    /// Warning: the Proteus client must be initialized with `proteusInit` first or an error will be returned.
    @available(*, deprecated, message: "Use proteusNewPrekeyAuto() instead.")
    public func proteusNewPrekey(prekeyId: UInt16) async throws -> Data {
        return try await coreCryptoContextFfi.proteusNewPrekey(prekeyId: prekeyId)
    }
}
