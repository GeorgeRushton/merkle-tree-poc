"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.StandardMerkleTree = void 0;

const keccak_1 = require("ethereum-cryptography/keccak");
const utils_1 = require("ethereum-cryptography/utils");
const abi_1 = require("@ethersproject/abi");
const bytes_1 = require("./bytes");
const core_1 = require("./core");
const check_bounds_1 = require("./utils/check-bounds");
const throw_error_1 = require("./utils/throw-error");
function standardLeafHash(value, types) {
    return (0, keccak_1.keccak256)((0, keccak_1.keccak256)((0, utils_1.hexToBytes)(abi_1.defaultAbiCoder.encode(types, value))));
}
function singleKeccakHash(value, types) {
    return (0, keccak_1.keccak256)((0, utils_1.hexToBytes)(abi_1.defaultAbiCoder.encode(types, value)));
}

class StandardMerkleTree {
    constructor(tree, values, leafEncoding) {
        this.tree = tree;
        this.values = values;
        this.leafEncoding = leafEncoding;
        // this.hashLookup =
        //     Object.fromEntries(values.map(({ value }, valueIndex) => [
        //         (0, bytes_1.hex)(standardLeafHash(value, leafEncoding)),
        //         valueIndex,
        //     ]));
    }
    static of(values, leafEncoding) {
        // console.log('started of() method of oz/standard.js')
        // // console.log('of() method of oz/standard.js - input values: ', values.slice(0,6))
        var hashStartTime = process.hrtime();
        const hashedValues = values
            .map((value, valueIndex) => ({ value, valueIndex, hash: singleKeccakHash(value, leafEncoding) }))
            // .sort((a, b) => (0, bytes_1.compareBytes)(a.hash, b.hash));

        // console.log('hashedValues format: ')
        // console.log(hashedValues.map(v => v.hash))

        var hashEndTime = process.hrtime(hashStartTime);
        var durationInSeconds = hashStartTime[0] + hashEndTime[1] / 1e9;
        // console.log(`hashing took ${durationInSeconds.toFixed(3)} seconds`, '\n');

        var treeBuildStartTime = process.hrtime();
        const tree = (0, core_1.makeMerkleTree)(hashedValues.map(v => v.hash));
        var treeBuildEndTime = process.hrtime(treeBuildStartTime);
        var durationInSeconds = treeBuildStartTime[0] + treeBuildEndTime[1] / 1e9;
        // console.log(`Method tree building took ${durationInSeconds.toFixed(3)} seconds`, '\n');

        // // console.log('of() method of oz/standard.js - tree: ', tree)
        var indexingStartTime = process.hrtime();
        const indexedValues = values.map(value => ({ value, treeIndex: 0 }));
        for (const [leafIndex, { valueIndex }] of hashedValues.entries()) {
            // // console.log(leafIndex, valueIndex)
            indexedValues[valueIndex].treeIndex = tree.length - leafIndex - 1;
        }
        var indexingEndTime = process.hrtime(indexingStartTime);
        var durationInSeconds = indexingStartTime[0] + indexingEndTime[1] / 1e9;
        // console.log(`Indexing  took ${durationInSeconds.toFixed(3)} seconds`, '\n');

        // // console.log('of() method of oz/standard.js - indexedValues: ', indexedValues)
        return new StandardMerkleTree(tree, indexedValues, leafEncoding);
    }
    static ofHashed(indexedValues, hashedValues, leafEncoding) {
        // // console.log('started ofHashed() method')
        // // console.log('hashedValues format: ')
        // // console.log(hashedValues)
        const tree = (0, core_1.makeMerkleTree)(hashedValues);
        // // console.log('made the tree')
        return new StandardMerkleTree(tree, indexedValues, leafEncoding);
    }
    updateLeaves(leafIndices, newValues) {
        // console.log('started updateLeaves method')
        // console.log('this is the original tree: ', this.tree.slice(0,1))

        const { updatedTree, updatedValues } = (0, core_1.updateMerkleTree)(this, leafIndices, newValues);
        
        // console.log('this is the updated tree: ', updatedTree.slice(0,1))

        this.tree = updatedTree
        this.values = updatedValues
    }
    static load(data) {
        if (data.format !== 'standard-v1') {
            throw new Error(`Unknown format '${data.format}'`);
        }
        return new StandardMerkleTree(data.tree.map(utils_1.hexToBytes), data.values, data.leafEncoding);
    }
    static verify(root, leafEncoding, leaf, proof) {
        const impliedRoot = (0, core_1.processProof)(singleKeccakHash(leaf, leafEncoding), proof.map(utils_1.hexToBytes));
        return (0, utils_1.equalsBytes)(impliedRoot, (0, utils_1.hexToBytes)(root));
    }
    static verifyMultiProof(root, leafEncoding, multiproof) {
        const leafHashes = multiproof.leaves.map(leaf => singleKeccakHash(leaf, leafEncoding));
        const proofBytes = multiproof.proof.map(utils_1.hexToBytes);
        const impliedRoot = (0, core_1.processMultiProof)({
            leaves: leafHashes,
            proof: proofBytes,
            proofFlags: multiproof.proofFlags,
        });
        return (0, utils_1.equalsBytes)(impliedRoot, (0, utils_1.hexToBytes)(root));
    }
    dump() {
        return {
            format: 'standard-v1',
            tree: this.tree.map(bytes_1.hex),
            values: this.values,
            leafEncoding: this.leafEncoding,
        };
    }
    render() {
        return (0, core_1.renderMerkleTree)(this.tree);
    }
    get root() {
        return (0, bytes_1.hex)(this.tree[0]);
    }
    *entries() {
        for (const [i, { value }] of this.values.entries()) {
            yield [i, value];
        }
    }
    validate() {
        for (let i = 0; i < this.values.length; i++) {
            this.validateValue(i);
        }
        if (!(0, core_1.isValidMerkleTree)(this.tree)) {
            throw new Error('Merkle tree is invalid');
        }
    }
    leafHash(leaf) {
        return (0, bytes_1.hex)(singleKeccakHash(leaf, this.leafEncoding));
    }
    // leafLookup(leaf) {
    //     return this.hashLookup[this.leafHash(leaf)] ?? (0, throw_error_1.throwError)('Leaf is not in tree');
    // }
    getProof(leaf) {
        // input validity
        // const valueIndex = typeof leaf === 'number' ? leaf : this.leafLookup(leaf);
        const valueIndex = leaf;
        this.validateValue(valueIndex);
        // rebuild tree index and generate proof
        const { treeIndex } = this.values[valueIndex];
        const proof = (0, core_1.getProof)(this.tree, treeIndex);
        // sanity check proof
        if (!this._verify(this.tree[treeIndex], proof)) {
            throw new Error('Unable to prove value');
        }
        // return proof in hex format
        return proof.map(bytes_1.hex);
    }
    getMultiProof(leaves) {

        // console.log('started getMultiProof in oz/standard.js')
        // // console.log('getMultiProof (oz/standard.js) this.values: ', this.values)
        // console.log('getMultiProof (oz/standard.js) input leaves: ', leaves)
        // input validity
        // const valueIndices = leaves.map(leaf => typeof leaf === 'number' ? leaf : this.leafLookup(leaf));
        const valueIndices = leaves;
        // console.log('getMultiProof (oz/standard.js) valueIndices: ', valueIndices)
        for (const valueIndex of valueIndices)
            this.validateValue(valueIndex);
        // rebuild tree indices and generate proof
        // // console.log('getMultiProof (oz/standard.js) this.values[0]: ', this.values[0])
        // // console.log('getMultiProof (oz/standard.js) this.values[1]: ', this.values[1])
        // // console.log('getMultiProof (oz/standard.js) this.values[2]: ', this.values[2])
        // // console.log('getMultiProof (oz/standard.js) this.values[3]: ', this.values[3])
        // // console.log('getMultiProof (oz/standard.js) this.values[4]: ', this.values[4])
        // // console.log('getMultiProof (oz/standard.js) this.values[5]: ', this.values[5])

        const indices = valueIndices.map(i => this.values[i].treeIndex);
        // console.log('getMultiProof (oz/standard.js) indices: ', indices)
        const proof = (0, core_1.getMultiProof)(this.tree, indices);
        // // console.log('getMultiProof (oz/standard.js) proof: ', proof)
        // sanity check proof
        if (!this._verifyMultiProof(proof)) {
            throw new Error('Unable to prove values');
        }
        // return multiproof in hex format
        return {
            // leaves: proof.leaves.map(hash => this.values[this.hashLookup[(0, bytes_1.hex)(hash)]].value),
            proof: proof.proof.map(bytes_1.hex),
            proofFlags: proof.proofFlags,
        };
    }
    verify(leaf, proof) {
        return this._verify(this.getLeafHash(leaf), proof.map(utils_1.hexToBytes));
    }
    _verify(leafHash, proof) {
        const impliedRoot = (0, core_1.processProof)(leafHash, proof);
        return (0, utils_1.equalsBytes)(impliedRoot, this.tree[0]);
    }
    verifyMultiProof(multiproof) {
        return this._verifyMultiProof({
            leaves: multiproof.leaves.map(l => this.getLeafHash(l)),
            proof: multiproof.proof.map(utils_1.hexToBytes),
            proofFlags: multiproof.proofFlags,
        });
    }
    _verifyMultiProof(multiproof) {
        const impliedRoot = (0, core_1.processMultiProof)(multiproof);
        return (0, utils_1.equalsBytes)(impliedRoot, this.tree[0]);
    }
    validateValue(valueIndex) {
        (0, check_bounds_1.checkBounds)(this.values, valueIndex);
        const { value, treeIndex } = this.values[valueIndex];
        (0, check_bounds_1.checkBounds)(this.tree, treeIndex);
        const leaf = singleKeccakHash(value, this.leafEncoding);
        if (!(0, utils_1.equalsBytes)(leaf, this.tree[treeIndex])) {
            throw new Error('Merkle tree does not contain the expected value');
        }
        return leaf;
    }
    getLeafHash(leaf) {
        if (typeof leaf === 'number') {
            return this.validateValue(leaf);
        }
        else {
            return singleKeccakHash(leaf, this.leafEncoding);
        }
    }
}
exports.StandardMerkleTree = StandardMerkleTree;
//# sourceMappingURL=standard.js.map