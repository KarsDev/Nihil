package me.kuwg.nihil.cypher;


import java.io.Serializable;
import java.util.Arrays;

public abstract class NihilKey implements Serializable, Cloneable {
    protected final byte[] bytes;

    protected NihilKey(final byte... bytes) {
        this.bytes = bytes;
    }

    public final byte[] getBytes() {
        return bytes;
    }

    @Override
    public abstract Object clone() throws CloneNotSupportedException;

    @Override
    public String toString() {
        return "NihilKey{" + "bytes=" + Arrays.toString(bytes) + '}';
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        return Arrays.equals(bytes, ((NihilKey) o).bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}
