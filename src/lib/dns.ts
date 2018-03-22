// https://tools.ietf.org/html/rfc1035

// TODO: check limits:
// 2.3.4. Size limits

// Various objects and parameters in the DNS have size limits.  They are
// listed below.  Some could be easily changed, others are more
// fundamental.

// labels          63 octets or less

// names           255 octets or less

// TTL             positive values of a signed 32 bit number.

// UDP messages    512 octets or less

export class DNSMessage {

	public constructor(
		public header: MessageHeader,
		public questions: Question[],
		public answers: ResourceRecord[],
		public authorities: ResourceRecord[],
		public additionalRecords: ResourceRecord[],
	) {
		// nada
	}

	public serialize(): Buffer {
		return Buffer.concat([
			this.header.serialize(),
			number2Buffer16(this.questions.length),
			number2Buffer16(this.answers.length),
			number2Buffer16(this.authorities.length),
			number2Buffer16(this.additionalRecords.length),
			...this.questions.map(q => q.serialize()),
			...this.answers.map(a => a.serialize()),
			...this.authorities.map(a => a.serialize()),
			...this.additionalRecords.map(a => a.serialize()),
		]);
	}
	public static deserialize(data: Buffer): DNSMessage {
		throw new Error("Method not implemented.");
	}

}

export class MessageHeader {

	public constructor(
		public id: number,
		public type: MessageType,
		public opcode: OPCode,
		public authoritative: boolean,
		public truncated: boolean,
		public recursionDesired: boolean,
		public recursionAvailable: boolean,
		public responseCode: number,
	) {
		// nada
	}

	public serialize(): Buffer {
		const byte3 = Buffer.from([
			this.type << 7 +
			(this.opcode & 0b1111) << 3 +
			(this.authoritative ? 1 : 0) << 2 +
			(this.truncated ? 1 : 0) << 1 +
			(this.recursionDesired ? 1 : 0),
		]);
		const byte4 = Buffer.from([
			(this.recursionAvailable ? 1 : 0) << 7 +
			(this.responseCode & 0b1111),
		]);
		return Buffer.concat([
			number2Buffer16(this.id),
			byte3, byte4,
		]);
	}

}

export class Question {

	public constructor(
		public name: DNSName,
		public type: QuestionType,
		public qclass: QuestionClass,
	) {
		// nada
	}

	public serialize(): Buffer {
		return Buffer.concat([
			this.name.serialize(),
			number2Buffer16(this.type),
			number2Buffer16(this.qclass),
		]);
	}

}

export class ResourceRecord {

	public constructor(
		public name: DNSName,
		public type: RecordType,
		public rclass: RecordClass,
		public ttl: number,
		public data: Buffer,
	) {
		// nada
	}

	public serialize(): Buffer {
		return Buffer.concat([
			this.name.serialize(),
			number2Buffer16(this.type),
			number2Buffer16(this.rclass),
			number2Buffer16(this.ttl),
			number2Buffer16(this.data.length),
			this.data,
		]);
	}
}

export class DNSName {

	public constructor(
		public labels: string[]
	) {
		// nada
	}

	public serialize(): Buffer {
		return Buffer.concat([
			...this.labels.map(l => serializeLabel(l))
		]);
	}

	public static deserialize(data: Buffer, offset: number): {bytesRead: number, result: DNSName} {
		const {bytesRead, labels} = parseLabels(data, offset);
		return {
			bytesRead,
			result: new DNSName(labels),
		}
	}

	public static fromString(str: string): DNSName {
		const labels = str.split(".");
		// the last (root) label is always empty
		if (labels[labels.length-1] != "") labels.push("");
		return new DNSName(labels);
	}

	public toString(): string {
		return this.labels
			// the last (root) label is always empty
			.filter((l, index) => index < this.labels.length-1 || l != "")
			.join(".")
		;
	}
}

export const enum MessageType {
	Query = 0,
	Response = 1,
}

export const enum OPCode {
	Query = 0,
	InverseQuery = 1,
	StatusRequest = 2,
	// 3..15 = reserved
}

export const enum ResponseCode {
	NoError = 0,
	FormatError = 1,
	ServerFailure = 2,
	NameError = 3,
	NotImplemented = 4,
	Refused = 5,
	// 6..15 = reserved
}

export const enum QuestionType {
	A,
	NS,
	MD,
	MF,
	CNAME,
	SOA,
	MB,
	MG,
	MR,
	NULL,
	WKS,
	PTR,
	HINFO,
	MINFO,
	MX,
	TXT,
	AXFR = 252,
	MAILB,
	MAILA,
	ANY = 255,
}

export const enum QuestionClass {
	IN = 1,
	CS,
	CH,
	HS,
	ANY = 255,
}

export const enum RecordType {
	A = 1,
	NS,
	MD,
	MF,
	CNAME,
	SOA,
	MB,
	MG,
	MR,
	NULL,
	WKS,
	PTR,
	HINFO,
	MINFO,
	MX,
	TXT,
}

export const enum RecordClass {
	IN = 1,
	CS,
	CH,
	HS,
}

function number2Buffer16(num: number): Buffer {
	const ret = new Buffer(2);
	ret.writeUInt16BE(num, 0);
	return ret;
}

function getLabelType(data: Buffer, offset: number) {
	switch (data[offset] >>> 6) {
		case 0: return "label";
		case 3: return "pointer";
		default: throw new Error("Unexpected data in entry label")
	}
}

/** 
 * Parses labels until reaching a root (=empty) label 
 */
function parseLabels(data: Buffer, offset: number): {bytesRead: number, labels: string[]} {
	let bytesRead: number;
	const labelType = getLabelType(data, offset);
	if (labelType === "label") {
		let label: string;
		({bytesRead, label} = parseLabel(data, offset));
		if (label === "") {
			// we reached the root label, we're done
			return {
				bytesRead,
				labels: [label],
			};
		} else {
			// continue parsing recursively
			let labels: string[]
			let additionalBytesRead: number;
			({bytesRead: additionalBytesRead, labels} = parseLabels(data, offset + bytesRead));
			return {
				bytesRead: bytesRead + additionalBytesRead,
				labels: [label, ...labels],
			};
		}
	} else if (labelType === "pointer") {
		const pointerTarget = getPointerTarget(data, offset);
		// we don't care about the #bytes at the pointer location,
		// the next entry is in 2 bytes
		let {labels} = parseLabels(data, pointerTarget);
		return {
			bytesRead: 2,
			labels,
		};
	}
}

/** parses a single label */
function parseLabel(data: Buffer, offset: number): {bytesRead: number, label: string} {
	const length = data[offset];
	const label = data.toString("utf8", offset + 1, offset + 1 + length);
	return {
		bytesRead: length + 1,
		label,
	};
}

function getPointerTarget(data: Buffer, offset: number): number {
	return data.readUInt16BE(offset) & 0b0011_1111_1111_1111;
}

function serializeLabel(label: string): Buffer {
	if (label.length > 63) throw new Error("Labels must be 63 bytes or less")
	return Buffer.concat([
		Buffer.from([label.length]),
		Buffer.from(label, "utf8"),
	]);
}
