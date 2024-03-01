"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderMerkleTree = exports.isValidMerkleTree = exports.processMultiProof = exports.getMultiProof = exports.processProof = exports.getProof = exports.makeMerkleTree = void 0;
const keccak_1 = require("ethereum-cryptography/keccak");
const utils_1 = require("ethereum-cryptography/utils");
const bytes_1 = require("./bytes");
const abi_1 = require("@ethersproject/abi");
const throw_error_1 = require("./utils/throw-error");
const hashPair = (a, b) => (0, keccak_1.keccak256)((0, utils_1.concatBytes)(...[a, b].sort(bytes_1.compareBytes)));
const leftChildIndex = (i) => 2 * i + 1;
const rightChildIndex = (i) => 2 * i + 2;
const parentIndex = (i) => i > 0 ? Math.floor((i - 1) / 2) : (0, throw_error_1.throwError)('Root has no parent');
const siblingIndex = (i) => i > 0 ? i - (-1) ** (i % 2) : (0, throw_error_1.throwError)('Root has no siblings');
const isTreeNode = (tree, i) => i >= 0 && i < tree.length;
const isInternalNode = (tree, i) => isTreeNode(tree, leftChildIndex(i));
const isLeafNode = (tree, i) => isTreeNode(tree, i) && !isInternalNode(tree, i);
const isValidMerkleNode = (node) => node instanceof Uint8Array && node.length === 32;
const checkTreeNode = (tree, i) => void (isTreeNode(tree, i) || (0, throw_error_1.throwError)('Index is not in tree'));
const checkInternalNode = (tree, i) => void (isInternalNode(tree, i) || (0, throw_error_1.throwError)('Index is not an internal tree node'));
const checkLeafNode = (tree, i) => void (isLeafNode(tree, i) || (0, throw_error_1.throwError)('Index is not a leaf'));
const checkValidMerkleNode = (node) => void (isValidMerkleNode(node) || (0, throw_error_1.throwError)('Merkle tree nodes must be Uint8Array of length 32'));
function standardLeafHash(value, types) {
    return (0, keccak_1.keccak256)((0, keccak_1.keccak256)((0, utils_1.hexToBytes)(abi_1.defaultAbiCoder.encode(types, value))));
}
function singleKeccakHash(value, types) {
    return (0, keccak_1.keccak256)((0, utils_1.hexToBytes)(abi_1.defaultAbiCoder.encode(types, value)));
}


function makeMerkleTree(leaves) {
    // leaves.forEach(checkValidMerkleNode);
    if (leaves.length === 0) {
        throw new Error('Expected non-zero number of leaves');
    }
    const tree = new Array(2 * leaves.length - 1);
    for (const [i, leaf] of leaves.entries()) {
        tree[tree.length - 1 - i] = leaf;
    }
    for (let i = tree.length - 1 - leaves.length; i >= 0; i--) {
        tree[i] = hashPair(tree[leftChildIndex(i)], tree[rightChildIndex(i)]);
    }
    return tree;
}
exports.makeMerkleTree = makeMerkleTree;


function updateMerkleTree(currentTreeObj, updateIndices, newLeavesUnhashed) {
    // console.log('started updateMerkleTree')
    const tree = currentTreeObj.tree
    const values = currentTreeObj.values 


    let leafEncoding = currentTreeObj.leafEncoding
    // console.log('updatedIndices = ', updateIndices)

    const numberOfLeaves = currentTreeObj.values.length;
    const numberOfLevels = Math.ceil(Math.log2(numberOfLeaves));
    // console.log('Number of levels in the tree:', numberOfLevels);


    // console.log('tree values before update: ', values.slice(0,7))
    // update values
    for (let i=0; i < updateIndices.length; i++) {
        let index = updateIndices[i]
        values[index].value = newLeavesUnhashed[i]
    }
    // console.log('tree values after update: ', values.slice(0,7))

    var parentIndices = []
    for (let j=0; j <= numberOfLevels; j++) {
        
        var currentLevelIndices = []
        if (j == 0) {
            currentLevelIndices = updateIndices.map((v,i) => {return tree.length - 1 - v})
        }
        else {
            currentLevelIndices = Array.from(new Set(parentIndices))
        }
        parentIndices = []
        // console.log('level ', j, 'this level indices are: ', currentLevelIndices)

        for (let i=0; i < currentLevelIndices.length; i++) {
            let index = currentLevelIndices[i]
    
            if (j == numberOfLevels) {
                // // console.log('level ' , j, ',  index: ', index,'level is root level')
                // // console.log('left childIndex: ', leftChildIndex(index))
                // // console.log('right childIndex: ', rightChildIndex(index))
                tree[index] = hashPair(tree[leftChildIndex(index)], tree[rightChildIndex(index)]);
            } else {
                let _siblingIndex = siblingIndex(index)
                let _parentIndex = parentIndex(index)
                // console.log('loop ', i, ' index: ', index, ', siblingOfUpdatedValuesTreeIndex: ', _siblingIndex,', parent: ', _parentIndex)
        
                parentIndices.push(_parentIndex)
                // console.log('parentIndices after push: ', parentIndices)

                // console.log('this is the current hash for this index:' , tree[index])

                if (j == 0) {
                    // console.log('level is 0 so hashing given leaves')
                    tree[index] = singleKeccakHash(newLeavesUnhashed[i], leafEncoding)
                } else {
                    // console.log('level ' , j, ',  index: ', index,'level is not 0 so setting hash as the combined hash of this indexes children')
                    // console.log('left childIndex: ', leftChildIndex(index))
                    // console.log('right childIndex: ', rightChildIndex(index))
                    tree[index] = hashPair(tree[leftChildIndex(index)], tree[rightChildIndex(index)]);
                }
            }

            // console.log('this is the new hash for this index:' , tree[index])
        }
        // console.log('level ', j, 'this level parentIindices are: ', parentIndices)
    }

    return { updatedTree: tree, updatedValues: values };
}
exports.updateMerkleTree = updateMerkleTree;



function makeMerkleTree2(updateIndices, leaves, oldTree) {
    // leaves.forEach(checkValidMerkleNode);
    // console.log('started makeMerkleTree2')
    // // console.log('here is oldTree', oldTree)
    // if (leaves.length === 0) {
    //     throw new Error('Expected non-zero number of leaves');
    // }
    // const tree = new Array(2 * leaves.length - 1);
    // for (const [i, leaf] of leaves.entries()) {
    //     tree[tree.length - 1 - i] = leaf;
    // }
    let tree = oldTree

    // console.log('updatedIndices = ', updateIndices)

    // console.log('oldTree needs to be updated for each index')

    // remember index 0 is 1999998 in old tree


    // for (let i=0; i < updateIndices.length; i++) {
    //     let index = updateIndices[i]
    //     // console.log('loop ', i, ' index: ', index)

    //     let updatedValuesTreeIndex = tree.length - 1 - i
    //     // console.log('loop ', i, ' index: ', index, ' updatedValuesTreeIndex: ', updatedValuesTreeIndex)

    //     let siblingOfUpdatedValuesTreeIndex = siblingIndex(updatedValuesTreeIndex)
    //     // console.log('loop ', i, ' index: ', index, ' siblingOfUpdatedValuesTreeIndex: ', siblingOfUpdatedValuesTreeIndex)

    //     let parentOfUpdatedValuesTreeindex = parentIndex(updatedValuesTreeIndex)
    //     // console.log('loop ', i, ' index: ', index, ' parentOfUpdatedValuesTreeindex: ', parentOfUpdatedValuesTreeindex)

    //     let leftChildOfParentOfUpdatedValuesTreeindex = leftChildIndex(parentOfUpdatedValuesTreeindex)
    //     // console.log('loop ', i, ' index: ', index, ' leftChildOfParentOfUpdatedValuesTreeindex: ', leftChildOfParentOfUpdatedValuesTreeindex)

    //     let rightChildOfParentOfUpdatedValuesTreeindex = rightChildIndex(parentOfUpdatedValuesTreeindex)
    //     // console.log('loop ', i, ' index: ', index, ' rightChildOfParentOfUpdatedValuesTreeindex: ', rightChildOfParentOfUpdatedValuesTreeindex)

    //     let siblingOfParentOfUpdatedValuesTreeindex = siblingIndex(parentOfUpdatedValuesTreeindex)
    //     // console.log('loop ', i, ' index: ', index, ' siblingOfParentOfUpdatedValuesTreeindex: ', siblingOfParentOfUpdatedValuesTreeindex)
    // }


    const numberOfLeaves = 1000000;
    const numberOfLevels = Math.ceil(Math.log2(numberOfLeaves));
    // console.log('Number of levels in the tree:', numberOfLevels);


    var parentIndices = []
    for (let j=0; j < numberOfLevels; j++) {
        
        var currentLevelIndices = []
        if (j == 0) {
            currentLevelIndices = updateIndices.map((v,i) => {return tree.length - 1 - v})
        }
        else {
            currentLevelIndices = Array.from(new Set(parentIndices))
        }
        parentIndices = []
        // console.log('level ', j, 'this level indices are: ', currentLevelIndices)

        for (let i=0; i < currentLevelIndices.length; i++) {
            let index = currentLevelIndices[i]
    
            let siblingIndex = siblingIndex(index)
            let parentIndex = parentIndex(index)
            // console.log('loop ', i, ' index: ', index, ', siblingOfUpdatedValuesTreeIndex: ', siblingIndex,', parent: ', parentIndex)
    
            parentIndices.push(parentIndex)
            // console.log('parentIndices after push: ', parentIndices)

            if (j == 0) {
                // console.log('level is 0 so hashing given leaves')
                tree[index] = singleKeccakHash(newLeavesUnhashed[i], leafEncoding)
            } else {
                // console.log('level ' , j, ',  index: ', index,'level is not 0 so setting hash as the combined hash of this indexes children')
                // console.log('left childIndex: ', leftChildIndex(index))
                // console.log('right childIndex: ', rightChildIndex(index))
                tree[index] = hashPair(tree[leftChildIndex(index)], tree[rightChildIndex(index)]);

            }
        }
        // console.log('level ', j, 'this level parentIindices are: ', parentIndices)
    }


    // for (let i = tree.length - 1 - leaves.length; i >= 0; i--) {
    //     tree[i] = hashPair(tree[leftChildIndex(i)], tree[rightChildIndex(i)]);
    // }
    return tree;
    // return oldTree
}
exports.makeMerkleTree2 = makeMerkleTree2;

function getProof(tree, index) {
    checkLeafNode(tree, index);
    const proof = [];
    while (index > 0) {
        proof.push(tree[siblingIndex(index)]);
        index = parentIndex(index);
    }
    return proof;
}
exports.getProof = getProof;
function processProof(leaf, proof) {
    checkValidMerkleNode(leaf);
    proof.forEach(checkValidMerkleNode);
    return proof.reduce(hashPair, leaf);
}
exports.processProof = processProof;
function getMultiProof(tree, indices) {

    // console.log('started getMultiProof (oz.core.js)')
    // // console.log('getMultiProof : tree:', tree)
    // console.log('getMultiProof : indices:', indices)
    indices.forEach(i => checkLeafNode(tree, i));
    // console.log('getMultiProof : indices after checkLeafNode:', indices)
    indices.sort((a, b) => b - a);
    // console.log('getMultiProof : indices after sort:', indices)
    if (indices.slice(1).some((i, p) => i === indices[p])) {
        throw new Error('Cannot prove duplicated index');
    }
    const stack = indices.concat(); // copy
    const proof = [];
    const proofFlags = [];
    while (stack.length > 0 && stack[0] > 0) {
        const j = stack.shift(); // take from the beginning
        const s = siblingIndex(j);
        const p = parentIndex(j);
        if (s === stack[0]) {
            proofFlags.push(true);
            stack.shift(); // consume from the stack
        }
        else {
            proofFlags.push(false);
            proof.push(tree[s]);
        }
        stack.push(p);
    }
    if (indices.length === 0) {
        proof.push(tree[0]);
    }

    // console.log('completed getMultiProof (oz.core.js)')

    return {
        leaves: indices.map(i => tree[i]),
        proof,
        proofFlags,
    };
}
exports.getMultiProof = getMultiProof;
function processMultiProof(multiproof) {
    multiproof.leaves.forEach(checkValidMerkleNode);
    multiproof.proof.forEach(checkValidMerkleNode);
    if (multiproof.proof.length < multiproof.proofFlags.filter(b => !b).length) {
        throw new Error('Invalid multiproof format');
    }
    if (multiproof.leaves.length + multiproof.proof.length !== multiproof.proofFlags.length + 1) {
        throw new Error('Provided leaves and multiproof are not compatible');
    }
    const stack = multiproof.leaves.concat(); // copy
    const proof = multiproof.proof.concat(); // copy
    for (const flag of multiproof.proofFlags) {
        const a = stack.shift();
        const b = flag ? stack.shift() : proof.shift();
        if (a === undefined || b === undefined) {
            throw new Error('Broken invariant');
        }
        stack.push(hashPair(a, b));
    }
    if (stack.length + proof.length !== 1) {
        throw new Error('Broken invariant');
    }
    return stack.pop() ?? proof.shift();
}
exports.processMultiProof = processMultiProof;
function isValidMerkleTree(tree) {
    for (const [i, node] of tree.entries()) {
        if (!isValidMerkleNode(node)) {
            return false;
        }
        const l = leftChildIndex(i);
        const r = rightChildIndex(i);
        if (r >= tree.length) {
            if (l < tree.length) {
                return false;
            }
        }
        else if (!(0, utils_1.equalsBytes)(node, hashPair(tree[l], tree[r]))) {
            return false;
        }
    }
    return tree.length > 0;
}
exports.isValidMerkleTree = isValidMerkleTree;
function renderMerkleTree(tree) {
    if (tree.length === 0) {
        throw new Error('Expected non-zero number of nodes');
    }
    const stack = [[0, []]];
    const lines = [];
    while (stack.length > 0) {
        const [i, path] = stack.pop();
        lines.push(path.slice(0, -1).map(p => ['   ', '│  '][p]).join('') +
            path.slice(-1).map(p => ['└─ ', '├─ '][p]).join('') +
            i + ') ' +
            (0, utils_1.bytesToHex)(tree[i]));
        if (rightChildIndex(i) < tree.length) {
            stack.push([rightChildIndex(i), path.concat(0)]);
            stack.push([leftChildIndex(i), path.concat(1)]);
        }
    }
    return lines.join('\n');
}
exports.renderMerkleTree = renderMerkleTree;
//# sourceMappingURL=core.js.map