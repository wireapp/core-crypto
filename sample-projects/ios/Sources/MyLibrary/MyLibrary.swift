// This file was autogenerated by some hot garbage in the `uniffi` crate.
// Trust me, you don't want to mess with it!
import Foundation

// Depending on the consumer's build setup, the low-level FFI code
// might be in a separate module, or it might be compiled inline into
// this module. This is a bit of light hackery to work with both.
#if canImport(CoreCrypto)
import CoreCrypto
#endif

fileprivate extension RustBuffer {
    // Allocate a new buffer, copying the contents of a `UInt8` array.
    init(bytes: [UInt8]) {
        let rbuf = bytes.withUnsafeBufferPointer { ptr in
            RustBuffer.from(ptr)
        }
        self.init(capacity: rbuf.capacity, len: rbuf.len, data: rbuf.data)
    }

    static func from(_ ptr: UnsafeBufferPointer<UInt8>) -> RustBuffer {
        try! rustCall { ffi_CoreCrypto_174_rustbuffer_from_bytes(ForeignBytes(bufferPointer: ptr), $0) }
    }

    // Frees the buffer in place.
    // The buffer must not be used after this is called.
    func deallocate() {
        try! rustCall { ffi_CoreCrypto_174_rustbuffer_free(self, $0) }
    }
}

fileprivate extension ForeignBytes {
    init(bufferPointer: UnsafeBufferPointer<UInt8>) {
        self.init(len: Int32(bufferPointer.count), data: bufferPointer.baseAddress)
    }
}

// For every type used in the interface, we provide helper methods for conveniently
// lifting and lowering that type from C-compatible data, and for reading and writing
// values of that type in a buffer.

// Helper classes/extensions that don't change.
// Someday, this will be in a libray of its own.

fileprivate extension Data {
    init(rustBuffer: RustBuffer) {
        // TODO: This copies the buffer. Can we read directly from a
        // Rust buffer?
        self.init(bytes: rustBuffer.data!, count: Int(rustBuffer.len))
    }
}

// A helper class to read values out of a byte buffer.
fileprivate class Reader {
    let data: Data
    var offset: Data.Index

    init(data: Data) {
        self.data = data
        self.offset = 0
    }

    // Reads an integer at the current offset, in big-endian order, and advances
    // the offset on success. Throws if reading the integer would move the
    // offset past the end of the buffer.
    func readInt<T: FixedWidthInteger>() throws -> T {
        let range = offset..<offset + MemoryLayout<T>.size
        guard data.count >= range.upperBound else {
            throw UniffiInternalError.bufferOverflow
        }
        if T.self == UInt8.self {
            let value = data[offset]
            offset += 1
            return value as! T
        }
        var value: T = 0
        let _ = withUnsafeMutableBytes(of: &value, { data.copyBytes(to: $0, from: range)})
        offset = range.upperBound
        return value.bigEndian
    }

    // Reads an arbitrary number of bytes, to be used to read
    // raw bytes, this is useful when lifting strings
    func readBytes(count: Int) throws -> Array<UInt8> {
        let range = offset..<(offset+count)
        guard data.count >= range.upperBound else {
            throw UniffiInternalError.bufferOverflow
        }
        var value = [UInt8](repeating: 0, count: count)
        value.withUnsafeMutableBufferPointer({ buffer in
            data.copyBytes(to: buffer, from: range)
        })
        offset = range.upperBound
        return value
    }

    // Reads a float at the current offset.
    @inlinable
    func readFloat() throws -> Float {
        return Float(bitPattern: try readInt())
    }

    // Reads a float at the current offset.
    @inlinable
    func readDouble() throws -> Double {
        return Double(bitPattern: try readInt())
    }

    // Indicates if the offset has reached the end of the buffer.
    @inlinable
    func hasRemaining() -> Bool {
        return offset < data.count
    }
}

// A helper class to write values into a byte buffer.
fileprivate class Writer {
    var bytes: [UInt8]
    var offset: Array<UInt8>.Index

    init() {
        self.bytes = []
        self.offset = 0
    }

    func writeBytes<S>(_ byteArr: S) where S: Sequence, S.Element == UInt8 {
        bytes.append(contentsOf: byteArr)
    }

    // Writes an integer in big-endian order.
    //
    // Warning: make sure what you are trying to write
    // is in the correct type!
    func writeInt<T: FixedWidthInteger>(_ value: T) {
        var value = value.bigEndian
        withUnsafeBytes(of: &value) { bytes.append(contentsOf: $0) }
    }

    @inlinable
    func writeFloat(_ value: Float) {
        writeInt(value.bitPattern)
    }

    @inlinable
    func writeDouble(_ value: Double) {
        writeInt(value.bitPattern)
    }
}


// Types conforming to `Serializable` can be read and written in a bytebuffer.
fileprivate protocol Serializable {
    func write(into: Writer)
    static func read(from: Reader) throws -> Self
}

// Types confirming to `ViaFfi` can be transferred back-and-for over the FFI.
// This is analogous to the Rust trait of the same name.
fileprivate protocol ViaFfi: Serializable {
    associatedtype FfiType
    static func lift(_ v: FfiType) throws -> Self
    func lower() -> FfiType
}

// Types conforming to `Primitive` pass themselves directly over the FFI.
fileprivate protocol Primitive {}

extension Primitive {
    fileprivate typealias FfiType = Self

    fileprivate static func lift(_ v: Self) throws -> Self {
        return v
    }

    fileprivate func lower() -> Self {
        return self
    }
}

// Types conforming to `ViaFfiUsingByteBuffer` lift and lower into a bytebuffer.
// Use this for complex types where it's hard to write a custom lift/lower.
fileprivate protocol ViaFfiUsingByteBuffer: Serializable {}

extension ViaFfiUsingByteBuffer {
    fileprivate typealias FfiType = RustBuffer

    fileprivate static func lift(_ buf: FfiType) throws -> Self {
      let reader = Reader(data: Data(rustBuffer: buf))
      let value = try Self.read(from: reader)
      if reader.hasRemaining() {
          throw UniffiInternalError.incompleteData
      }
      buf.deallocate()
      return value
    }

    fileprivate func lower() -> FfiType {
      let writer = Writer()
      self.write(into: writer)
      return RustBuffer(bytes: writer.bytes)
    }
}
// An error type for FFI errors. These errors occur at the UniFFI level, not
// the library level.
fileprivate enum UniffiInternalError: LocalizedError {
    case bufferOverflow
    case incompleteData
    case unexpectedOptionalTag
    case unexpectedEnumCase
    case unexpectedNullPointer
    case unexpectedRustCallStatusCode
    case unexpectedRustCallError
    case unexpectedStaleHandle
    case rustPanic(_ message: String)

    public var errorDescription: String? {
        switch self {
        case .bufferOverflow: return "Reading the requested value would read past the end of the buffer"
        case .incompleteData: return "The buffer still has data after lifting its containing value"
        case .unexpectedOptionalTag: return "Unexpected optional tag; should be 0 or 1"
        case .unexpectedEnumCase: return "Raw enum value doesn't match any cases"
        case .unexpectedNullPointer: return "Raw pointer value was null"
        case .unexpectedRustCallStatusCode: return "Unexpected RustCallStatus code"
        case .unexpectedRustCallError: return "CALL_ERROR but no errorClass specified"
        case .unexpectedStaleHandle: return "The object in the handle map has been dropped already"
        case let .rustPanic(message): return message
        }
    }
}

fileprivate let CALL_SUCCESS: Int8 = 0
fileprivate let CALL_ERROR: Int8 = 1
fileprivate let CALL_PANIC: Int8 = 2

fileprivate extension RustCallStatus {
    init() {
        self.init(
            code: CALL_SUCCESS,
            errorBuf: RustBuffer.init(
                capacity: 0,
                len: 0,
                data: nil
            )
        )
    }
}

private func rustCall<T>(_ callback: (UnsafeMutablePointer<RustCallStatus>) -> T) throws -> T {
    try makeRustCall(callback, errorHandler: {
        $0.deallocate()
        return UniffiInternalError.unexpectedRustCallError
    })
}

private func rustCallWithError<T, E: ViaFfiUsingByteBuffer & Error>(_ errorClass: E.Type, _ callback: (UnsafeMutablePointer<RustCallStatus>) -> T) throws -> T {
    try makeRustCall(callback, errorHandler: { return try E.lift($0) })
}

private func makeRustCall<T>(_ callback: (UnsafeMutablePointer<RustCallStatus>) -> T, errorHandler: (RustBuffer) throws -> Error) throws -> T {
    var callStatus = RustCallStatus.init()
    let returnedVal = callback(&callStatus)
    switch callStatus.code {
        case CALL_SUCCESS:
            return returnedVal

        case CALL_ERROR:
            throw try errorHandler(callStatus.errorBuf)

        case CALL_PANIC:
            // When the rust code sees a panic, it tries to construct a RustBuffer
            // with the message.  But if that code panics, then it just sends back
            // an empty buffer.
            if callStatus.errorBuf.len > 0 {
                throw UniffiInternalError.rustPanic(try String.lift(callStatus.errorBuf))
            } else {
                callStatus.errorBuf.deallocate()
                throw UniffiInternalError.rustPanic("Rust panic")
            }

        default:
            throw UniffiInternalError.unexpectedRustCallStatusCode
    }
}
// Protocols for converters we'll implement in templates

fileprivate protocol FfiConverter {
    associatedtype SwiftType
    associatedtype FfiType

    static func lift(_ ffiValue: FfiType) throws -> SwiftType
    static func lower(_ value: SwiftType) -> FfiType

    static func read(from: Reader) throws -> SwiftType
    static func write(_ value: SwiftType, into: Writer)
}

fileprivate protocol FfiConverterUsingByteBuffer: FfiConverter where FfiType == RustBuffer {
    // Empty, because we want to declare some helper methods in the extension below.
}

extension FfiConverterUsingByteBuffer {
    static func lower(_ value: SwiftType) -> FfiType {
        let writer = Writer()
        Self.write(value, into: writer)
        return RustBuffer(bytes: writer.bytes)
    }

    static func lift(_ buf: FfiType) throws -> SwiftType {
        let reader = Reader(data: Data(rustBuffer: buf))
        let value = try Self.read(from: reader)
        if reader.hasRemaining() {
          throw UniffiInternalError.incompleteData
        }
        buf.deallocate()
        return value
    }
}

// Helpers for structural types. Note that because of canonical_names, it /should/ be impossible
// to make another `FfiConverterSequence` etc just using the UDL.
fileprivate enum FfiConverterSequence {
    static func write<T>(_ value: [T], into buf: Writer, writeItem: (T, Writer) -> Void) {
        let len = Int32(value.count)
        buf.writeInt(len)
        for item in value {
            writeItem(item, buf)
        }
    }

    static func read<T>(from buf: Reader, readItem: (Reader) throws -> T) throws -> [T] {
        let len: Int32 = try buf.readInt()
        var seq = [T]()
        seq.reserveCapacity(Int(len))
        for _ in 0 ..< len {
            seq.append(try readItem(buf))
        }
        return seq
    }
}

fileprivate enum FfiConverterOptional {
    static func write<T>(_ value: T?, into buf: Writer, writeItem: (T, Writer) -> Void) {
        guard let value = value else {
            buf.writeInt(Int8(0))
            return
        }
        buf.writeInt(Int8(1))
        writeItem(value, buf)
    }

    static func read<T>(from buf: Reader, readItem: (Reader) throws -> T) throws -> T? {
        switch try buf.readInt() as Int8 {
        case 0: return nil
        case 1: return try readItem(buf)
        default: throw UniffiInternalError.unexpectedOptionalTag
        }
    }
}

fileprivate enum FfiConverterDictionary {
    static func write<T>(_ value: [String: T], into buf: Writer, writeItem: (String, T, Writer) -> Void) {
        let len = Int32(value.count)
        buf.writeInt(len)
        for (key, value) in value {
            writeItem(key, value, buf)
        }
    }

    static func read<T>(from buf: Reader, readItem: (Reader) throws -> (String, T)) throws -> [String: T] {
        let len: Int32 = try buf.readInt()
        var dict = [String: T]()
        dict.reserveCapacity(Int(len))
        for _ in 0..<len {
            let (key, value) = try readItem(buf)
            dict[key] = value
        }
        return dict
    }
}

// Public interface members begin here.



// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.

public enum CiphersuiteName {
    
    case mls10128Dhkemx25519Aes128gcmSha256Ed25519
    case mls10128Dhkemp256Aes128gcmSha256P256
    case mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519
    case mls10256Dhkemx448Aes256gcmSha512Ed448
    case mls10256Dhkemp521Aes256gcmSha512P521
    case mls10256Dhkemx448Chacha20poly1305Sha512Ed448
    case mls10256Dhkemp384Aes256gcmSha384P384
}

extension CiphersuiteName: ViaFfiUsingByteBuffer, ViaFfi {
    fileprivate static func read(from buf: Reader) throws -> CiphersuiteName {
        let variant: Int32 = try buf.readInt()
        switch variant {
        
        case 1: return .mls10128Dhkemx25519Aes128gcmSha256Ed25519
        case 2: return .mls10128Dhkemp256Aes128gcmSha256P256
        case 3: return .mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519
        case 4: return .mls10256Dhkemx448Aes256gcmSha512Ed448
        case 5: return .mls10256Dhkemp521Aes256gcmSha512P521
        case 6: return .mls10256Dhkemx448Chacha20poly1305Sha512Ed448
        case 7: return .mls10256Dhkemp384Aes256gcmSha384P384
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    fileprivate func write(into buf: Writer) {
        switch self {
        
        
        case .mls10128Dhkemx25519Aes128gcmSha256Ed25519:
            buf.writeInt(Int32(1))
        
        
        case .mls10128Dhkemp256Aes128gcmSha256P256:
            buf.writeInt(Int32(2))
        
        
        case .mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519:
            buf.writeInt(Int32(3))
        
        
        case .mls10256Dhkemx448Aes256gcmSha512Ed448:
            buf.writeInt(Int32(4))
        
        
        case .mls10256Dhkemp521Aes256gcmSha512P521:
            buf.writeInt(Int32(5))
        
        
        case .mls10256Dhkemx448Chacha20poly1305Sha512Ed448:
            buf.writeInt(Int32(6))
        
        
        case .mls10256Dhkemp384Aes256gcmSha384P384:
            buf.writeInt(Int32(7))
        
        }
    }
}


extension CiphersuiteName: Equatable, Hashable {}



public func initWithPathAndKey( path: String,  key: String,  clientId: String ) throws -> CoreCrypto {
    let _retval = try
    
    
    rustCallWithError(CryptoError.self) {
    
    CoreCrypto_174_init_with_path_and_key(path.lower(), key.lower(), clientId.lower() , $0)
}
    return try CoreCrypto.lift(_retval)
}



public func version()  -> String {
    let _retval = try!
    
    
    rustCall() {
    
    CoreCrypto_174_version( $0)
}
    return try! String.lift(_retval)
}



public protocol CoreCryptoProtocol {
    func createConversation( conversationId: String,  config: ConversationConfiguration ) throws -> ConversationCreationMessage?
    func decryptMessage( conversationId: String,  payload: [UInt8] ) throws -> [UInt8]?
    func encryptMessage( conversationId: String,  message: [UInt8] ) throws -> [UInt8]
    
}

public class CoreCrypto: CoreCryptoProtocol {
    fileprivate let pointer: UnsafeMutableRawPointer

    // TODO: We'd like this to be `private` but for Swifty reasons,
    // we can't implement `ViaFfi` without making this `required` and we can't
    // make it `required` without making it `public`.
    required init(unsafeFromRawPointer pointer: UnsafeMutableRawPointer) {
        self.pointer = pointer
    }
    public convenience init( path: String,  key: String,  clientId: String ) throws {
        self.init(unsafeFromRawPointer: try
    
    
    rustCallWithError(CryptoError.self) {
    
    CoreCrypto_174_CoreCrypto_new(path.lower(), key.lower(), clientId.lower() , $0)
})
    }

    deinit {
        try! rustCall { ffi_CoreCrypto_174_CoreCrypto_object_free(pointer, $0) }
    }

    

    
    public func createConversation( conversationId: String,  config: ConversationConfiguration ) throws -> ConversationCreationMessage? {
        let _retval = try
    rustCallWithError(CryptoError.self) {
    
    CoreCrypto_174_CoreCrypto_create_conversation(self.pointer, FfiConverterTypeConversationId.lower(conversationId), config.lower() , $0
    )
}
        return try FfiConverterOptionRecordConversationCreationMessage.lift(_retval)
    }
    public func decryptMessage( conversationId: String,  payload: [UInt8] ) throws -> [UInt8]? {
        let _retval = try
    rustCallWithError(CryptoError.self) {
    
    CoreCrypto_174_CoreCrypto_decrypt_message(self.pointer, FfiConverterTypeConversationId.lower(conversationId), FfiConverterSequenceUInt8.lower(payload) , $0
    )
}
        return try FfiConverterOptionSequenceUInt8.lift(_retval)
    }
    public func encryptMessage( conversationId: String,  message: [UInt8] ) throws -> [UInt8] {
        let _retval = try
    rustCallWithError(CryptoError.self) {
    
    CoreCrypto_174_CoreCrypto_encrypt_message(self.pointer, FfiConverterTypeConversationId.lower(conversationId), FfiConverterSequenceUInt8.lower(message) , $0
    )
}
        return try FfiConverterSequenceUInt8.lift(_retval)
    }
    
}


fileprivate extension CoreCrypto {
    typealias FfiType = UnsafeMutableRawPointer

    static func read(from buf: Reader) throws -> Self {
        let v: UInt64 = try buf.readInt()
        // The Rust code won't compile if a pointer won't fit in a UInt64.
        // We have to go via `UInt` because that's the thing that's the size of a pointer.
        let ptr = UnsafeMutableRawPointer(bitPattern: UInt(truncatingIfNeeded: v))
        if (ptr == nil) {
            throw UniffiInternalError.unexpectedNullPointer
        }
        return try self.lift(ptr!)
    }

    func write(into buf: Writer) {
        // This fiddling is because `Int` is the thing that's the same size as a pointer.
        // The Rust code won't compile if a pointer won't fit in a `UInt64`.
        buf.writeInt(UInt64(bitPattern: Int64(Int(bitPattern: self.lower()))))
    }

    static func lift(_ pointer: UnsafeMutableRawPointer) throws -> Self {
        return Self(unsafeFromRawPointer: pointer)
    }

    func lower() -> UnsafeMutableRawPointer {
        return self.pointer
    }
}

// Ideally this would be `fileprivate`, but Swift says:
// """
// 'private' modifier cannot be used with extensions that declare protocol conformances
// """
extension CoreCrypto : ViaFfi, Serializable {}

public struct ConversationCreationMessage {
    public var message: [UInt8]
    public var welcome: [UInt8]

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(message: [UInt8], welcome: [UInt8] ) {
        self.message = message
        self.welcome = welcome
    }
}


extension ConversationCreationMessage: Equatable, Hashable {
    public static func ==(lhs: ConversationCreationMessage, rhs: ConversationCreationMessage) -> Bool {
        if lhs.message != rhs.message {
            return false
        }
        if lhs.welcome != rhs.welcome {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(message)
        hasher.combine(welcome)
    }
}


fileprivate extension ConversationCreationMessage {
    static func read(from buf: Reader) throws -> ConversationCreationMessage {
        return try ConversationCreationMessage(
            message: FfiConverterSequenceUInt8.read(from: buf),
            welcome: FfiConverterSequenceUInt8.read(from: buf)
        )
    }

    func write(into buf: Writer) {
        FfiConverterSequenceUInt8.write(self.message, into: buf)
        FfiConverterSequenceUInt8.write(self.welcome, into: buf)
    }
}

extension ConversationCreationMessage: ViaFfiUsingByteBuffer, ViaFfi {}

public struct Invitee {
    public var id: String
    public var kp: [UInt8]

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(id: String, kp: [UInt8] ) {
        self.id = id
        self.kp = kp
    }
}


extension Invitee: Equatable, Hashable {
    public static func ==(lhs: Invitee, rhs: Invitee) -> Bool {
        if lhs.id != rhs.id {
            return false
        }
        if lhs.kp != rhs.kp {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
        hasher.combine(kp)
    }
}


fileprivate extension Invitee {
    static func read(from buf: Reader) throws -> Invitee {
        return try Invitee(
            id: FfiConverterTypeClientId.read(buf),
            kp: FfiConverterSequenceUInt8.read(from: buf)
        )
    }

    func write(into buf: Writer) {
        FfiConverterTypeClientId.write(self.id, buf)
        FfiConverterSequenceUInt8.write(self.kp, into: buf)
    }
}

extension Invitee: ViaFfiUsingByteBuffer, ViaFfi {}

public struct ConversationConfiguration {
    public var extraMembers: [Invitee]
    public var admins: [String]
    public var ciphersuite: CiphersuiteName?
    public var keyRotationSpan: TimeInterval?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(extraMembers: [Invitee], admins: [String], ciphersuite: CiphersuiteName?, keyRotationSpan: TimeInterval? ) {
        self.extraMembers = extraMembers
        self.admins = admins
        self.ciphersuite = ciphersuite
        self.keyRotationSpan = keyRotationSpan
    }
}


extension ConversationConfiguration: Equatable, Hashable {
    public static func ==(lhs: ConversationConfiguration, rhs: ConversationConfiguration) -> Bool {
        if lhs.extraMembers != rhs.extraMembers {
            return false
        }
        if lhs.admins != rhs.admins {
            return false
        }
        if lhs.ciphersuite != rhs.ciphersuite {
            return false
        }
        if lhs.keyRotationSpan != rhs.keyRotationSpan {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(extraMembers)
        hasher.combine(admins)
        hasher.combine(ciphersuite)
        hasher.combine(keyRotationSpan)
    }
}


fileprivate extension ConversationConfiguration {
    static func read(from buf: Reader) throws -> ConversationConfiguration {
        return try ConversationConfiguration(
            extraMembers: FfiConverterSequenceRecordInvitee.read(from: buf),
            admins: FfiConverterSequenceMemberId.read(from: buf),
            ciphersuite: FfiConverterOptionEnumCiphersuiteName.read(from: buf),
            keyRotationSpan: FfiConverterOptionDuration.read(from: buf)
        )
    }

    func write(into buf: Writer) {
        FfiConverterSequenceRecordInvitee.write(self.extraMembers, into: buf)
        FfiConverterSequenceMemberId.write(self.admins, into: buf)
        FfiConverterOptionEnumCiphersuiteName.write(self.ciphersuite, into: buf)
        FfiConverterOptionDuration.write(self.keyRotationSpan, into: buf)
    }
}

extension ConversationConfiguration: ViaFfiUsingByteBuffer, ViaFfi {}

public enum CryptoError {

    
    
    // Simple error enums only carry a message
    case ConversationNotFound(message: String)
    
    // Simple error enums only carry a message
    case MalformedIdentifier(message: String)
    
    // Simple error enums only carry a message
    case KeyStoreError(message: String)
    
    // Simple error enums only carry a message
    case ClientSignatureNotFound(message: String)
    
    // Simple error enums only carry a message
    case OutOfKeyPackage(message: String)
    
    // Simple error enums only carry a message
    case LockPoisonError(message: String)
    
    // Simple error enums only carry a message
    case ConversationConfigurationError(message: String)
    
    // Simple error enums only carry a message
    case CentralConfigurationError(message: String)
    
    // Simple error enums only carry a message
    case MlsError(message: String)
    
    // Simple error enums only carry a message
    case UuidError(message: String)
    
    // Simple error enums only carry a message
    case Utf8Error(message: String)
    
    // Simple error enums only carry a message
    case ParseIntError(message: String)
    
    // Simple error enums only carry a message
    case Other(message: String)
    
}

extension CryptoError: ViaFfiUsingByteBuffer, ViaFfi {
    fileprivate static func read(from buf: Reader) throws -> CryptoError {
        let variant: Int32 = try buf.readInt()
        switch variant {

        

        
        case 1: return .ConversationNotFound(
            message: try String.read(from: buf)
        )
        
        case 2: return .MalformedIdentifier(
            message: try String.read(from: buf)
        )
        
        case 3: return .KeyStoreError(
            message: try String.read(from: buf)
        )
        
        case 4: return .ClientSignatureNotFound(
            message: try String.read(from: buf)
        )
        
        case 5: return .OutOfKeyPackage(
            message: try String.read(from: buf)
        )
        
        case 6: return .LockPoisonError(
            message: try String.read(from: buf)
        )
        
        case 7: return .ConversationConfigurationError(
            message: try String.read(from: buf)
        )
        
        case 8: return .CentralConfigurationError(
            message: try String.read(from: buf)
        )
        
        case 9: return .MlsError(
            message: try String.read(from: buf)
        )
        
        case 10: return .UuidError(
            message: try String.read(from: buf)
        )
        
        case 11: return .Utf8Error(
            message: try String.read(from: buf)
        )
        
        case 12: return .ParseIntError(
            message: try String.read(from: buf)
        )
        
        case 13: return .Other(
            message: try String.read(from: buf)
        )
        

         default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    fileprivate func write(into buf: Writer) {
        switch self {

        

        
        case let .ConversationNotFound(message):
            buf.writeInt(Int32(1))
            message.write(into: buf)
        case let .MalformedIdentifier(message):
            buf.writeInt(Int32(2))
            message.write(into: buf)
        case let .KeyStoreError(message):
            buf.writeInt(Int32(3))
            message.write(into: buf)
        case let .ClientSignatureNotFound(message):
            buf.writeInt(Int32(4))
            message.write(into: buf)
        case let .OutOfKeyPackage(message):
            buf.writeInt(Int32(5))
            message.write(into: buf)
        case let .LockPoisonError(message):
            buf.writeInt(Int32(6))
            message.write(into: buf)
        case let .ConversationConfigurationError(message):
            buf.writeInt(Int32(7))
            message.write(into: buf)
        case let .CentralConfigurationError(message):
            buf.writeInt(Int32(8))
            message.write(into: buf)
        case let .MlsError(message):
            buf.writeInt(Int32(9))
            message.write(into: buf)
        case let .UuidError(message):
            buf.writeInt(Int32(10))
            message.write(into: buf)
        case let .Utf8Error(message):
            buf.writeInt(Int32(11))
            message.write(into: buf)
        case let .ParseIntError(message):
            buf.writeInt(Int32(12))
            message.write(into: buf)
        case let .Other(message):
            buf.writeInt(Int32(13))
            message.write(into: buf)
        }
    }
}


extension CryptoError: Equatable, Hashable {}

extension CryptoError: Error { }
fileprivate struct FfiConverterTypeClientId {
    fileprivate static func read(_ buf: Reader) throws -> String {
        return try String.read(from: buf)
    }

    fileprivate static func write(_ value: String, _ buf: Writer) {
        return value.write(into: buf)
    }

    fileprivate static func lift(_ value: RustBuffer) throws -> String {
        return try String.lift(value)
    }

    fileprivate static func lower(_ value: String) -> RustBuffer {
        return value.lower()
    }
}
fileprivate struct FfiConverterTypeConversationId {
    fileprivate static func read(_ buf: Reader) throws -> String {
        return try String.read(from: buf)
    }

    fileprivate static func write(_ value: String, _ buf: Writer) {
        return value.write(into: buf)
    }

    fileprivate static func lift(_ value: RustBuffer) throws -> String {
        return try String.lift(value)
    }

    fileprivate static func lower(_ value: String) -> RustBuffer {
        return value.lower()
    }
}
fileprivate struct FfiConverterTypeMemberId {
    fileprivate static func read(_ buf: Reader) throws -> String {
        return try String.read(from: buf)
    }

    fileprivate static func write(_ value: String, _ buf: Writer) {
        return value.write(into: buf)
    }

    fileprivate static func lift(_ value: RustBuffer) throws -> String {
        return try String.lift(value)
    }

    fileprivate static func lower(_ value: String) -> RustBuffer {
        return value.lower()
    }
}
extension UInt8: Primitive, ViaFfi {
    fileprivate static func read(from buf: Reader) throws -> Self {
        return try self.lift(buf.readInt())
    }

    fileprivate func write(into buf: Writer) {
        buf.writeInt(self.lower())
    }
}
extension String: ViaFfi {
    fileprivate typealias FfiType = RustBuffer

    fileprivate static func lift(_ v: FfiType) throws -> Self {
        defer {
            v.deallocate()
        }
        if v.data == nil {
            return String()
        }
        let bytes = UnsafeBufferPointer<UInt8>(start: v.data!, count: Int(v.len))
        return String(bytes: bytes, encoding: String.Encoding.utf8)!
    }

    fileprivate func lower() -> FfiType {
        return self.utf8CString.withUnsafeBufferPointer { ptr in
            // The swift string gives us int8_t, we want uint8_t.
            ptr.withMemoryRebound(to: UInt8.self) { ptr in
                // The swift string gives us a trailing null byte, we don't want it.
                let buf = UnsafeBufferPointer(rebasing: ptr.prefix(upTo: ptr.count - 1))
                return RustBuffer.from(buf)
            }
        }
    }

    fileprivate static func read(from buf: Reader) throws -> Self {
        let len: Int32 = try buf.readInt()
        return String(bytes: try buf.readBytes(count: Int(len)), encoding: String.Encoding.utf8)!
    }

    fileprivate func write(into buf: Writer) {
        let len = Int32(self.utf8.count)
        buf.writeInt(len)
        buf.writeBytes(self.utf8)
    }
}
extension TimeInterval: ViaFfiUsingByteBuffer, ViaFfi {
    fileprivate static func read(from buf: Reader) throws -> Self {
        let seconds: UInt64 = try buf.readInt()
        let nanoseconds: UInt32 = try buf.readInt()
        return Double(seconds) + (Double(nanoseconds) / 1.0e9)
    }

    fileprivate func write(into buf: Writer) {
        if self.rounded(.down) > Double(Int64.max) {
            fatalError("Duration overflow, exceeds max bounds supported by Uniffi")
        }

        if self < 0 {
            fatalError("Invalid duration, must be non-negative")
        }

        let seconds = UInt64(self)
        let nanoseconds = UInt32((self - Double(seconds)) * 1.0e9)
        buf.writeInt(seconds)
        buf.writeInt(nanoseconds)
    }
}
// Helper code for CoreCrypto class is found in ObjectTemplate.swift
// Helper code for ConversationConfiguration record is found in RecordTemplate.swift
// Helper code for ConversationCreationMessage record is found in RecordTemplate.swift
// Helper code for Invitee record is found in RecordTemplate.swift
// Helper code for CiphersuiteName enum is found in EnumTemplate.swift
// Helper code for CryptoError error is found in ErrorTemplate.swift

fileprivate enum FfiConverterOptionDuration: FfiConverterUsingByteBuffer {
    typealias SwiftType = TimeInterval?

    static func write(_ value: SwiftType, into buf: Writer) {
        FfiConverterOptional.write(value, into: buf) { item, buf in
            item.write(into: buf)
        }
    }

    static func read(from buf: Reader) throws -> SwiftType {
        try FfiConverterOptional.read(from: buf) { buf in
            try TimeInterval.read(from: buf)
        }
    }
}

fileprivate enum FfiConverterOptionRecordConversationCreationMessage: FfiConverterUsingByteBuffer {
    typealias SwiftType = ConversationCreationMessage?

    static func write(_ value: SwiftType, into buf: Writer) {
        FfiConverterOptional.write(value, into: buf) { item, buf in
            item.write(into: buf)
        }
    }

    static func read(from buf: Reader) throws -> SwiftType {
        try FfiConverterOptional.read(from: buf) { buf in
            try ConversationCreationMessage.read(from: buf)
        }
    }
}

fileprivate enum FfiConverterOptionEnumCiphersuiteName: FfiConverterUsingByteBuffer {
    typealias SwiftType = CiphersuiteName?

    static func write(_ value: SwiftType, into buf: Writer) {
        FfiConverterOptional.write(value, into: buf) { item, buf in
            item.write(into: buf)
        }
    }

    static func read(from buf: Reader) throws -> SwiftType {
        try FfiConverterOptional.read(from: buf) { buf in
            try CiphersuiteName.read(from: buf)
        }
    }
}

fileprivate enum FfiConverterOptionSequenceUInt8: FfiConverterUsingByteBuffer {
    typealias SwiftType = [UInt8]?

    static func write(_ value: SwiftType, into buf: Writer) {
        FfiConverterOptional.write(value, into: buf) { item, buf in
            FfiConverterSequenceUInt8.write(item, into: buf)
        }
    }

    static func read(from buf: Reader) throws -> SwiftType {
        try FfiConverterOptional.read(from: buf) { buf in
            try FfiConverterSequenceUInt8.read(from: buf)
        }
    }
}

fileprivate enum FfiConverterSequenceUInt8: FfiConverterUsingByteBuffer {
    typealias SwiftType = [UInt8]

    static func write(_ value: SwiftType, into buf: Writer) {
        FfiConverterSequence.write(value, into: buf) { (item, buf) in
            item.write(into: buf)
        }
    }

    static func read(from buf: Reader) throws -> SwiftType {
        try FfiConverterSequence.read(from: buf) { buf in
            try UInt8.read(from: buf)
        }
    }
}

fileprivate enum FfiConverterSequenceRecordInvitee: FfiConverterUsingByteBuffer {
    typealias SwiftType = [Invitee]

    static func write(_ value: SwiftType, into buf: Writer) {
        FfiConverterSequence.write(value, into: buf) { (item, buf) in
            item.write(into: buf)
        }
    }

    static func read(from buf: Reader) throws -> SwiftType {
        try FfiConverterSequence.read(from: buf) { buf in
            try Invitee.read(from: buf)
        }
    }
}

fileprivate enum FfiConverterSequenceMemberId: FfiConverterUsingByteBuffer {
    typealias SwiftType = [String]

    static func write(_ value: SwiftType, into buf: Writer) {
        FfiConverterSequence.write(value, into: buf) { (item, buf) in
            FfiConverterTypeMemberId.write(item, buf)
        }
    }

    static func read(from buf: Reader) throws -> SwiftType {
        try FfiConverterSequence.read(from: buf) { buf in
            try FfiConverterTypeMemberId.read(buf)
        }
    }
}
// Helper code for ClientId is found in CustomType.py
// Helper code for ConversationId is found in CustomType.py
// Helper code for MemberId is found in CustomType.py


/**
 * Top level initializers and tear down methods.
 *
 * This is generated by uniffi.
 */
public enum CoreCryptoLifecycle {
    /**
     * Initialize the FFI and Rust library. This should be only called once per application.
     */
    func initialize() {
        
        // No initialization code needed
        
    }
}
