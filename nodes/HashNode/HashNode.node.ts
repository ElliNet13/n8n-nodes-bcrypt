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
		description: 'Hash a password with bcrypt',
		defaults: {
			name: 'Bcrypt Hash',
		},
		inputs: [NodeConnectionType.Main],
		outputs: [NodeConnectionType.Main],
		usableAsTool: true,
		properties: [
			{
				displayName: 'Salt Rounds',
				name: 'saltRounds',
				type: 'number',
				default: 10,
				placeholder: 'Default: 10',
				description: 'How many salt rounds to apply when hashing the password',
			},
			{
				displayName: 'Plain Text Password',
				name: 'password',
				type: 'string',
				typeOptions: { password: true },
				default: '',
				placeholder: 'Enter the plain text password',
				description: 'The password to be hashed',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			try {
				const saltRounds = this.getNodeParameter('saltRounds', itemIndex, 10) as number;
				const password = this.getNodeParameter('password', itemIndex, '') as string;

				if (!password) {
					throw new NodeOperationError(this.getNode(), 'Password cannot be empty.', { itemIndex });
				}

				const hash = await bcrypt.hash(password, saltRounds);

				const newItem: INodeExecutionData = {
					json: {
						...items[itemIndex].json,
						hashedPassword: hash,
					},
				};

				returnData.push(newItem);

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
