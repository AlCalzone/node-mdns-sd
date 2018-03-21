// https://tools.ietf.org/html/rfc1035

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
		// public questionCount: number,
		// public answerCount: number,
		// public nameServerCount: number,
		// public additionalRecordCount: number,
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
		public labels: string[],
		public type: QuestionType,
		public qclass: QuestionClass,
	) {
		// nada
	}

	public serialize(): Buffer {
		return Buffer.concat([
			...this.labels.map(l => serializeLabel(l)),
			number2Buffer16(this.type),
			number2Buffer16(this.qclass),
		]);
	}

}

export class ResourceRecord {

	public constructor(
		public name: string,
		public type: RecordType,
		public rclass: RecordClass,
		public ttl: number,
		public data: Buffer,
	) {
		// nada
	}

	public serialize(): Buffer {
		return Buffer.concat([
			// TODO: how is the name serialized?!
			number2Buffer16(this.type),
			number2Buffer16(this.rclass),
			number2Buffer16(this.ttl),
			number2Buffer16(this.data.length),
			this.data,
		]);
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
	ret.writeUInt16LE(num, 0);
	return ret;
}

function serializeLabel(label: string): Buffer {
	return Buffer.concat([
		Buffer.from([label.length]),
		Buffer.from(label, "utf8"),
	]);
}
