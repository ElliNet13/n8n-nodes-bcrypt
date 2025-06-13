import type {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeConnectionType, NodeOperationError } from 'n8n-workflow';
const bcrypt = require('bcrypt');

export class HashNode implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Bcrypt Hash',
		name: 'hashNode',
		group: ['transform'],
		version: 1,
		description: 'Hash or compare passwords with bcrypt',
		defaults: {
			name: 'Bcrypt Hash',
		},
		inputs: [NodeConnectionType.Main],
		outputs: [NodeConnectionType.Main],
		usableAsTool: true,
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Hash',
						value: 'hash',
						description: 'Hash a password',
						action: 'Hash a password',
					},
					{
						name: 'Compare',
						value: 'compare',
						description: 'Compare password against hash',
						action: 'Compare password against hash',
					},
				],
				default: 'hash',
			},
			{
				displayName: 'Salt Rounds',
				name: 'saltRounds',
				type: 'number',
				default: 10,
				placeholder: 'Default: 10',
				description: 'How many salt rounds to apply when hashing the password',
				displayOptions: {
					show: {
						operation: ['hash'],
					},
				},
			},
			{
				displayName: 'Plain Text Password',
				name: 'password',
				type: 'string',
				typeOptions: { password: true },
				default: '',
				placeholder: 'Enter the plain text password',
				description: 'The password to hash or compare',
			},
			{
				displayName: 'Hash to Compare',
				name: 'hashToCompare',
				type: 'string',
				typeOptions: { password: true },
				default: '',
				placeholder: 'Enter the existing hash',
				description: 'The bcrypt hash to compare the password against',
				displayOptions: {
					show: {
						operation: ['compare'],
					},
				},
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			try {
				const operation = this.getNodeParameter('operation', itemIndex) as string;
				const password = this.getNodeParameter('password', itemIndex, '') as string;

				if (!password) {
					throw new NodeOperationError(this.getNode(), 'Password cannot be empty.', { itemIndex });
				}

				if (operation === 'hash') {
					const saltRounds = this.getNodeParameter('saltRounds', itemIndex, 10) as number;

					const hash = await bcrypt.hash(password, saltRounds);

					const newItem: INodeExecutionData = {
						json: {
							...items[itemIndex].json,
							hashedPassword: hash,
						},
					};

					returnData.push(newItem);

				} else if (operation === 'compare') {
					const hashToCompare = this.getNodeParameter('hashToCompare', itemIndex, '') as string;

					if (!hashToCompare) {
						throw new NodeOperationError(this.getNode(), 'Hash to compare cannot be empty.', { itemIndex });
					}

					const isMatch = await bcrypt.compare(password, hashToCompare);

					const newItem: INodeExecutionData = {
						json: {
							...items[itemIndex].json,
							passwordMatches: isMatch,
						},
					};

					returnData.push(newItem);
				}
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({ json: { error: (error as Error).message }, pairedItem: itemIndex });
				} else {
					throw new NodeOperationError(this.getNode(), error, { itemIndex });
				}
			}
		}

		return [returnData];
	}
}
