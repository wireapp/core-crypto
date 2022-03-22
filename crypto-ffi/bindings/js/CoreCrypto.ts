// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.


// @ts-ignore
import wasm from "../../../crypto-ffi/Cargo.toml";

import type * as CoreCryptoFfiTypes from "./wasm/core-crypto-ffi";

import type { Ciphersuite } from "./wasm/core-crypto-ffi";
export type { Ciphersuite } from "./wasm/core-crypto-ffi";

let CoreCryptoFfiModule: typeof CoreCryptoFfiTypes;

type Buffer = Uint8Array;
export interface ConversationConfiguration {
  admins?: Buffer[];
  ciphersuite?: Ciphersuite;
  keyRotationSpan?: number;
}

export type ConversationId = Buffer;

export interface CoreCryptoParams {
  path: string;
  key: string;
  clientId: string;
}

export interface Invitee {
  id: Buffer;
  kp: Buffer;
}

export interface MemberAddedMessages {
  message: Buffer;
  welcome: Buffer;
}

export interface ConversationLeaveMessages {
  self_removal_proposal: Buffer;
  other_clients_removal_commit: Buffer;
}

export const enum ProposalType {
  Add,
  Remove,
  Update,
}

export interface ProposalArgs {
  conversationId: string;
}

export interface AddProposalArgs extends ProposalArgs {
  kp: Buffer;
}

export interface RemoveProposalArgs extends ProposalArgs {
  clientId: string;
}

export class CoreCrypto {
  #cc: CoreCryptoFfiTypes.CoreCrypto;
  #encoder: TextEncoder;

  static async init(params: CoreCryptoParams): Promise<CoreCrypto> {
    const exports = (await wasm()) as typeof CoreCryptoFfiTypes;
    CoreCryptoFfiModule = exports;
    return new CoreCrypto(params);
  }

  constructor({ path, key, clientId }: CoreCryptoParams) {
    if (!CoreCryptoFfiModule) {
      throw new Error(
        "Internal module hasn't been initialized. Please use `await CoreCrypto.init(params)`!"
      );
    }
    this.#cc = new CoreCryptoFfiModule.CoreCrypto(path, key, clientId);
    this.#encoder = new TextEncoder();
  }

  createConversation(
    conversationId: string,
    { ciphersuite, keyRotationSpan }: ConversationConfiguration
  ) {
    const config = new CoreCryptoFfiModule.ConversationConfiguration(
      ciphersuite,
      keyRotationSpan
    );
    this.#cc.create_conversation(this.#encoder.encode(conversationId), config);
  }

  decryptMessage(conversationId: string, payload: Buffer): Buffer | undefined {
    return this.#cc.decrypt_message(
      this.#encoder.encode(conversationId),
      payload
    );
  }

  encryptMessage(conversationId: string, message: Buffer): Buffer {
    return this.#cc.encrypt_message(
      this.#encoder.encode(conversationId),
      message
    );
  }

  processWelcomeMessage(welcomeMessage: Buffer): ConversationId {
    return this.#cc.process_welcome_message(welcomeMessage);
  }

  clientPublicKey(): Buffer {
    return this.#cc.client_public_key();
  }

  clientKeypackages(amountRequested: number): Array<Buffer> {
    return this.#cc.client_keypackages(amountRequested);
  }

  addClientsToConversation(
    conversationId: string,
    clients: Invitee[]
  ): MemberAddedMessages | undefined {
    const ffiClients = clients.map(
      (invitee) => new CoreCryptoFfiModule.Invitee(invitee.id, invitee.kp)
    );
    const ffiRet = this.#cc.add_clients_to_conversation(
      this.#encoder.encode(conversationId),
      ffiClients
    );

    if (!ffiRet) {
      return;
    }

    const ret: MemberAddedMessages = {
      welcome: ffiRet.welcome,
      message: ffiRet.message,
    };

    ffiRet.free();

    return ret;
  }

  removeClientsFromConversation(
    conversationId: string,
    clientIds: string[]
  ): Buffer | undefined {
    const ffiClientsIds = clientIds.map((cid) => this.#encoder.encode(cid));
    return this.#cc.remove_clients_from_conversation(
      this.#encoder.encode(conversationId),
      ffiClientsIds
    );
  }

  conversationExists(conversationId: ConversationId): boolean {
    return this.#cc.conversation_exists(conversationId);
  }

  leaveConversation(
    conversationId: ConversationId,
    otherClients: Buffer[]
  ): ConversationLeaveMessages {
    const retFfi = this.#cc.leave_conversation(conversationId, otherClients);
    const ret: ConversationLeaveMessages = {
      self_removal_proposal: retFfi.self_removal_proposal,
      other_clients_removal_commit: retFfi.self_removal_proposal,
    };
    retFfi.free();
    return ret;
  }

  newProposal(
    proposalType: ProposalType,
    args: ProposalArgs | AddProposalArgs | RemoveProposalArgs
  ): Buffer {
    switch (proposalType) {
      case ProposalType.Add: {
        if (!(args as AddProposalArgs).kp) {
          throw new Error("kp is not contained in the proposal arguments");
        }
        return this.#cc.new_add_proposal(
          this.#encoder.encode(args.conversationId),
          (args as AddProposalArgs).kp
        );
      }
      case ProposalType.Remove: {
        if (!(args as RemoveProposalArgs).clientId) {
          throw new Error(
            "clientId is not contained in the proposal arguments"
          );
        }
        return this.#cc.new_remove_proposal(
          this.#encoder.encode(args.conversationId),
          this.#encoder.encode((args as RemoveProposalArgs).clientId)
        );
      }
      case ProposalType.Update: {
        return this.#cc.new_update_proposal(
          this.#encoder.encode(args.conversationId)
        );
      }
      default:
        throw new Error("Invalid proposal type!");
    }
  }

  wipe() {
    this.#cc.wipe();
    this.#cc.free();
  }

  close() {
    this.#cc.free();
  }

  static version(): string {
    if (!CoreCryptoFfiModule) {
      throw new Error(
        "Internal module hasn't been initialized. Please use `await CoreCrypto.init(params)`!"
      );
    }
    return CoreCryptoFfiModule.version();
  }
}
