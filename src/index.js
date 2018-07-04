/* eslint no-bitwise: "off" */
/* eslint no-restricted-syntax: "off" */
import Debug from 'debug';
import { Transform } from 'stream';

const debug = Debug('ubx:protocol:parser');

const PACKET_SYNC_1 = 0;
const PACKET_SYNC_2 = 1;
const PACKET_CLASS = 2;
const PACKET_ID = 3;
const PACKET_LENGTH = 4;
const PACKET_LENGTH_2 = 5;
const PACKET_PAYLOAD = 6;
const PACKET_CHECKSUM = 7;

const packetTemplate = {
  class: 0,
  id: 0,
  length: 0,
  payload: null,
  checksum: 0,
};

function calcCheckSum(messageClass, id, length, payload) {
  let buffer = Buffer.alloc(4);
  buffer.writeUInt8(messageClass, 0);
  buffer.writeUInt8(id, 1);
  buffer.writeUInt16LE(length, 2);
  buffer = Buffer.concat([buffer, payload]);

  let a = 0;
  let b = 0;

  for (let i = 0; i < buffer.length; i += 1) {
    [a] = new Uint8Array([(a + buffer[i])]);
    [b] = new Uint8Array([(b + a)]);
  }

  return (b << 8) | a;
}

export default class UBXProtocolParser extends Transform {
  constructor(options) {
    super({
      ...options,
      objectMode: true,
    });

    this.buffer = Buffer.alloc(0);
    this.packet = { ...packetTemplate };
    this.payloadPosition = 0;
    this.packetStartFound = false;
    this.packetState = 0;
  }

  _transform(chunk, encoding, cb) {
    const data = Buffer.concat([this.buffer, chunk]);
    let checksum;

    for (const [i, byte] of data.entries()) {
      if (this.packetStartFound) {
        switch (this.packetState) {
          case PACKET_SYNC_1:
            if (byte === 0x62) {
              this.packetState = PACKET_SYNC_2;
            } else {
              debug(`Unknown byte "${byte}" received at state "${this.packetState}"`);
              this.resetState();
            }
            break;

          case PACKET_SYNC_2:
            this.packet.class = byte;
            this.packetState = PACKET_CLASS;
            break;

          case PACKET_CLASS:
            this.packet.id = byte;
            this.packetState = PACKET_ID;
            break;

          case PACKET_ID:
            this.packet.length = byte;
            this.packetState = PACKET_LENGTH;
            break;

          case PACKET_LENGTH:
            this.packet.length = this.packet.length + byte * 2 ** 8;
            this.packetState = PACKET_LENGTH_2;
            break;

          case PACKET_LENGTH_2:
            if (this.packet.payload === null) {
              this.packet.payload = Buffer.alloc(this.packet.length);
              this.payloadPosition = 0;
            }

            this.packet.payload[this.payloadPosition] = byte;
            this.payloadPosition += 1;

            if (this.payloadPosition >= this.packet.length) {
              this.packetState = PACKET_PAYLOAD;
            }

            break;

          case PACKET_PAYLOAD:
            this.packet.checksum = byte;
            this.packetState = PACKET_CHECKSUM;
            break;

          case PACKET_CHECKSUM:
            this.packet.checksum = this.packet.checksum + byte * 2 ** 8;

            checksum = calcCheckSum(
              this.packet.class,
              this.packet.id,
              this.packet.length,
              this.packet.payload,
            );

            if (checksum === this.packet.checksum) {
              this.push({
                messageClass: this.packet.class,
                messageId: this.packet.id,
                payload: this.packet.payload,
              });
            } else {
              debug(`Checksum "${checksum}" doesn't match received CheckSum "${this.packet.checksum}"`);
            }

            this.resetState();
            this.buffer = data.slice(i + 1);
            break;
          default:
            debug(`Should never reach this packetState "${this.packetState}`);
        }
      } else if (byte === 0xB5) {
        this.packetStartFound = true;
        this.packetState = PACKET_SYNC_1;
      } else {
        debug(`Unknown byte "${byte}" received at state "${this.packetState}"`);
      }
    }

    cb();
  }

  resetState() {
    this.packetState = 0;
    this.packet = { ...packetTemplate };
    this.payloadPosition = 0;
    this.packetStartFound = false;
    this.buffer = Buffer.alloc(0);
  }

  _flush(cb) {
    this.resetState();
    cb();
  }
}
