package io.ont.proof;

import com.github.ontio.common.UInt256;

import java.util.Arrays;

public class Proof {
    public Proof() {
    }

    public UInt256 root;
    public int size, blockHeight, index;
    public UInt256[] proof;

    public Proof(UInt256 root, int size, int blockheight, int index, UInt256[] proof) {
        this.root = root;
        this.size = size;
        this.blockHeight = blockheight;
        this.index = index;
        this.proof = proof;
    }

    public UInt256 getRoot() {
        return root;
    }

    public int getSize() {
        return size;
    }

    public int getBlockHeight() {
        return blockHeight;
    }

    public int getIndex() {
        return index;
    }

    public UInt256[] getProof() {
        return proof;
    }

    @Override
    public String toString() {
        return String.format("block height: %d, size: %d, index: %d, root: %s, proof: %s", blockHeight, size, index, root, Arrays.toString(proof));
    }
}
