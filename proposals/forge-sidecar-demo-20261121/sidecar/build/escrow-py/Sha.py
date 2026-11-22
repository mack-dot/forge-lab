import sys
from typing import Callable, Any, TypeVar, NamedTuple
from math import floor
from itertools import count

import module_ as module_
import _dafny as _dafny
import System_ as System_

# Module: Sha

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def Xor32(a, b):
        hresult_: int = int(0)
        hresult_ = ((((((a) >> (16)) ^ ((b) >> (16))) << (16)) & ((1 << 32) - 1)) + (((a) & (65535)) ^ ((b) & (65535)))) & ((1 << 32) - 1)
        return hresult_
        return hresult_

    @staticmethod
    def And32(a, b):
        hresult_: int = int(0)
        hresult_ = ((((((a) >> (16)) & ((b) >> (16))) << (16)) & ((1 << 32) - 1)) + (((a) & (65535)) & ((b) & (65535)))) & ((1 << 32) - 1)
        return hresult_
        return hresult_

    @staticmethod
    def Or32(a, b):
        hresult_: int = int(0)
        hresult_ = ((((((a) >> (16)) | ((b) >> (16))) << (16)) & ((1 << 32) - 1)) + (((a) & (65535)) | ((b) & (65535)))) & ((1 << 32) - 1)
        return hresult_
        return hresult_

    @staticmethod
    def Not32(a):
        return (~(a)) & ((1 << 32) - 1)

    @staticmethod
    def RotR32(x, n):
        return default__.Or32((x) >> (n), ((x) << ((32) - (n))) & ((1 << 32) - 1))

    @staticmethod
    def Shr32(x, n):
        return (x) >> (n)

    @staticmethod
    def Xor64(a, b):
        hresult_: int = int(0)
        hresult_ = ((((((((((a) >> (48)) ^ ((b) >> (48))) << (48)) & ((1 << 64) - 1)) + ((((((a) >> (32)) & (65535)) ^ (((b) >> (32)) & (65535))) << (32)) & ((1 << 64) - 1))) & ((1 << 64) - 1)) + ((((((a) >> (16)) & (65535)) ^ (((b) >> (16)) & (65535))) << (16)) & ((1 << 64) - 1))) & ((1 << 64) - 1)) + (((a) & (65535)) ^ ((b) & (65535)))) & ((1 << 64) - 1)
        return hresult_
        return hresult_

    @staticmethod
    def And64(a, b):
        hresult_: int = int(0)
        hresult_ = ((((((((((a) >> (48)) & ((b) >> (48))) << (48)) & ((1 << 64) - 1)) + ((((((a) >> (32)) & (65535)) & (((b) >> (32)) & (65535))) << (32)) & ((1 << 64) - 1))) & ((1 << 64) - 1)) + ((((((a) >> (16)) & (65535)) & (((b) >> (16)) & (65535))) << (16)) & ((1 << 64) - 1))) & ((1 << 64) - 1)) + (((a) & (65535)) & ((b) & (65535)))) & ((1 << 64) - 1)
        return hresult_
        return hresult_

    @staticmethod
    def Or64(a, b):
        hresult_: int = int(0)
        hresult_ = ((((((((((a) >> (48)) | ((b) >> (48))) << (48)) & ((1 << 64) - 1)) + ((((((a) >> (32)) & (65535)) | (((b) >> (32)) & (65535))) << (32)) & ((1 << 64) - 1))) & ((1 << 64) - 1)) + ((((((a) >> (16)) & (65535)) | (((b) >> (16)) & (65535))) << (16)) & ((1 << 64) - 1))) & ((1 << 64) - 1)) + (((a) & (65535)) | ((b) & (65535)))) & ((1 << 64) - 1)
        return hresult_
        return hresult_

    @staticmethod
    def Not64(a):
        return (~(a)) & ((1 << 64) - 1)

    @staticmethod
    def RotR64(x, n):
        return default__.Or64((x) >> (n), ((x) << ((64) - (n))) & ((1 << 64) - 1))

    @staticmethod
    def ByteToBv32(b):
        return b

    @staticmethod
    def Bv32ToByte(w):
        return (w) & (255)

    @staticmethod
    def BE32(s, i):
        return (((((((((s)[i]) << (24)) & ((1 << 32) - 1)) + ((((s)[(i) + (1)]) << (16)) & ((1 << 32) - 1))) & ((1 << 32) - 1)) + ((((s)[(i) + (2)]) << (8)) & ((1 << 32) - 1))) & ((1 << 32) - 1)) + ((s)[(i) + (3)])) & ((1 << 32) - 1)

    @staticmethod
    def Bv32ToBE(w):
        return _dafny.SeqWithoutIsStrInference([((w) >> (24)) & (255), ((w) >> (16)) & (255), ((w) >> (8)) & (255), (w) & (255)])

    @staticmethod
    def BE64(s, i):
        return (((((((((((((((((s)[i]) << (56)) & ((1 << 64) - 1)) + ((((s)[(i) + (1)]) << (48)) & ((1 << 64) - 1))) & ((1 << 64) - 1)) + ((((s)[(i) + (2)]) << (40)) & ((1 << 64) - 1))) & ((1 << 64) - 1)) + ((((s)[(i) + (3)]) << (32)) & ((1 << 64) - 1))) & ((1 << 64) - 1)) + ((((s)[(i) + (4)]) << (24)) & ((1 << 64) - 1))) & ((1 << 64) - 1)) + ((((s)[(i) + (5)]) << (16)) & ((1 << 64) - 1))) & ((1 << 64) - 1)) + ((((s)[(i) + (6)]) << (8)) & ((1 << 64) - 1))) & ((1 << 64) - 1)) + ((s)[(i) + (7)])) & ((1 << 64) - 1)

    @staticmethod
    def Bv64ToBE(w):
        return _dafny.SeqWithoutIsStrInference([((w) >> (56)) & (255), ((w) >> (48)) & (255), ((w) >> (40)) & (255), ((w) >> (32)) & (255), ((w) >> (24)) & (255), ((w) >> (16)) & (255), ((w) >> (8)) & (255), (w) & (255)])

    @staticmethod
    def Pad(msg):
        d_0_ml_ = (len(msg)) * (8)
        d_1_withOne_ = (msg) + (_dafny.SeqWithoutIsStrInference([128]))
        d_2_k_ = _dafny.euclidian_modulus(((56) - (_dafny.euclidian_modulus(len(d_1_withOne_), 64))) + (64), 64)
        d_3_zeros_ = _dafny.SeqWithoutIsStrInference([0 for d_4_i_ in range(d_2_k_)])
        d_5_lenBytes_ = _dafny.SeqWithoutIsStrInference([_dafny.euclidian_modulus(_dafny.euclidian_division(d_0_ml_, 72057594037927936), 256), _dafny.euclidian_modulus(_dafny.euclidian_division(d_0_ml_, 281474976710656), 256), _dafny.euclidian_modulus(_dafny.euclidian_division(d_0_ml_, 1099511627776), 256), _dafny.euclidian_modulus(_dafny.euclidian_division(d_0_ml_, 4294967296), 256), _dafny.euclidian_modulus(_dafny.euclidian_division(d_0_ml_, 16777216), 256), _dafny.euclidian_modulus(_dafny.euclidian_division(d_0_ml_, 65536), 256), _dafny.euclidian_modulus(_dafny.euclidian_division(d_0_ml_, 256), 256), _dafny.euclidian_modulus(d_0_ml_, 256)])
        return ((d_1_withOne_) + (d_3_zeros_)) + (d_5_lenBytes_)

    @staticmethod
    def Ch32(e, f, g):
        return default__.Xor32(default__.And32(e, f), default__.And32(default__.Not32(e), g))

    @staticmethod
    def Maj32(a, b, c):
        return default__.Xor32(default__.Xor32(default__.And32(a, b), default__.And32(a, c)), default__.And32(b, c))

    @staticmethod
    def BigS0(a):
        return default__.Xor32(default__.Xor32(default__.RotR32(a, 2), default__.RotR32(a, 13)), default__.RotR32(a, 22))

    @staticmethod
    def BigS1(e):
        return default__.Xor32(default__.Xor32(default__.RotR32(e, 6), default__.RotR32(e, 11)), default__.RotR32(e, 25))

    @staticmethod
    def Sig0(x):
        return default__.Xor32(default__.Xor32(default__.RotR32(x, 7), default__.RotR32(x, 18)), default__.Shr32(x, 3))

    @staticmethod
    def Sig1(x):
        return default__.Xor32(default__.Xor32(default__.RotR32(x, 17), default__.RotR32(x, 19)), default__.Shr32(x, 10))

    @staticmethod
    def BuildW256(block):
        w: _dafny.Seq = _dafny.Seq({})
        d_0_ws_: _dafny.Array
        nw0_ = _dafny.Array(int(0), 64)
        d_0_ws_ = nw0_
        d_1_t_: int
        d_1_t_ = 0
        while (d_1_t_) < (16):
            (d_0_ws_)[(d_1_t_)] = default__.BE32(block, (d_1_t_) * (4))
            d_1_t_ = (d_1_t_) + (1)
        d_1_t_ = 16
        while (d_1_t_) < (64):
            (d_0_ws_)[(d_1_t_)] = ((((((default__.Sig1((d_0_ws_)[(d_1_t_) - (2)])) + ((d_0_ws_)[(d_1_t_) - (7)])) & ((1 << 32) - 1)) + (default__.Sig0((d_0_ws_)[(d_1_t_) - (15)]))) & ((1 << 32) - 1)) + ((d_0_ws_)[(d_1_t_) - (16)])) & ((1 << 32) - 1)
            d_1_t_ = (d_1_t_) + (1)
        w = _dafny.SeqWithoutIsStrInference((d_0_ws_)[::])
        return w

    @staticmethod
    def Sha256(msg):
        digest: _dafny.Seq = _dafny.Seq({})
        d_0_padded_: _dafny.Seq
        d_0_padded_ = default__.Pad(msg)
        d_1_h0_: int
        d_1_h0_ = 1779033703
        d_2_h1_: int
        d_2_h1_ = 3144134277
        d_3_h2_: int
        d_3_h2_ = 1013904242
        d_4_h3_: int
        d_4_h3_ = 2773480762
        d_5_h4_: int
        d_5_h4_ = 1359893119
        d_6_h5_: int
        d_6_h5_ = 2600822924
        d_7_h6_: int
        d_7_h6_ = 528734635
        d_8_h7_: int
        d_8_h7_ = 1541459225
        d_9_nblocks_: int
        d_9_nblocks_ = _dafny.euclidian_division(len(d_0_padded_), 64)
        d_10_bi_: int
        d_10_bi_ = 0
        while (d_10_bi_) < (d_9_nblocks_):
            d_11_start_: int
            d_11_start_ = (d_10_bi_) * (64)
            if ((d_11_start_) + (64)) <= (len(d_0_padded_)):
                d_12_block_: _dafny.Seq
                d_12_block_ = _dafny.SeqWithoutIsStrInference((d_0_padded_)[d_11_start_:(d_11_start_) + (64):])
                d_13_w_: _dafny.Seq
                out0_: _dafny.Seq
                out0_ = default__.BuildW256(d_12_block_)
                d_13_w_ = out0_
                d_14_a_: int
                d_14_a_ = d_1_h0_
                d_15_b_: int
                d_15_b_ = d_2_h1_
                d_16_c_: int
                d_16_c_ = d_3_h2_
                d_17_d_: int
                d_17_d_ = d_4_h3_
                d_18_e_: int
                d_18_e_ = d_5_h4_
                d_19_f_: int
                d_19_f_ = d_6_h5_
                d_20_g_: int
                d_20_g_ = d_7_h6_
                d_21_h_: int
                d_21_h_ = d_8_h7_
                d_22_t_: int
                d_22_t_ = 0
                while (d_22_t_) < (64):
                    d_23_t1_: int
                    d_23_t1_ = ((((((((d_21_h_) + (default__.BigS1(d_18_e_))) & ((1 << 32) - 1)) + (default__.Ch32(d_18_e_, d_19_f_, d_20_g_))) & ((1 << 32) - 1)) + ((default__.K256)[d_22_t_])) & ((1 << 32) - 1)) + ((d_13_w_)[d_22_t_])) & ((1 << 32) - 1)
                    d_24_t2_: int
                    d_24_t2_ = ((default__.BigS0(d_14_a_)) + (default__.Maj32(d_14_a_, d_15_b_, d_16_c_))) & ((1 << 32) - 1)
                    d_21_h_ = d_20_g_
                    d_20_g_ = d_19_f_
                    d_19_f_ = d_18_e_
                    d_18_e_ = ((d_17_d_) + (d_23_t1_)) & ((1 << 32) - 1)
                    d_17_d_ = d_16_c_
                    d_16_c_ = d_15_b_
                    d_15_b_ = d_14_a_
                    d_14_a_ = ((d_23_t1_) + (d_24_t2_)) & ((1 << 32) - 1)
                    d_22_t_ = (d_22_t_) + (1)
                d_1_h0_ = ((d_1_h0_) + (d_14_a_)) & ((1 << 32) - 1)
                d_2_h1_ = ((d_2_h1_) + (d_15_b_)) & ((1 << 32) - 1)
                d_3_h2_ = ((d_3_h2_) + (d_16_c_)) & ((1 << 32) - 1)
                d_4_h3_ = ((d_4_h3_) + (d_17_d_)) & ((1 << 32) - 1)
                d_5_h4_ = ((d_5_h4_) + (d_18_e_)) & ((1 << 32) - 1)
                d_6_h5_ = ((d_6_h5_) + (d_19_f_)) & ((1 << 32) - 1)
                d_7_h6_ = ((d_7_h6_) + (d_20_g_)) & ((1 << 32) - 1)
                d_8_h7_ = ((d_8_h7_) + (d_21_h_)) & ((1 << 32) - 1)
            d_10_bi_ = (d_10_bi_) + (1)
        digest = (((((((default__.Bv32ToBE(d_1_h0_)) + (default__.Bv32ToBE(d_2_h1_))) + (default__.Bv32ToBE(d_3_h2_))) + (default__.Bv32ToBE(d_4_h3_))) + (default__.Bv32ToBE(d_5_h4_))) + (default__.Bv32ToBE(d_6_h5_))) + (default__.Bv32ToBE(d_7_h6_))) + (default__.Bv32ToBE(d_8_h7_))
        return digest

    @staticmethod
    def Pad128(msg):
        d_0_ml_ = (len(msg)) * (8)
        d_1_withOne_ = (msg) + (_dafny.SeqWithoutIsStrInference([128]))
        d_2_k_ = _dafny.euclidian_modulus(((112) - (_dafny.euclidian_modulus(len(d_1_withOne_), 128))) + (128), 128)
        d_3_zeros_ = _dafny.SeqWithoutIsStrInference([0 for d_4_i_ in range(d_2_k_)])
        d_5_lenBytes_ = (_dafny.SeqWithoutIsStrInference([0 for d_6_i_ in range(8)])) + (_dafny.SeqWithoutIsStrInference([_dafny.euclidian_modulus(_dafny.euclidian_division(d_0_ml_, 72057594037927936), 256), _dafny.euclidian_modulus(_dafny.euclidian_division(d_0_ml_, 281474976710656), 256), _dafny.euclidian_modulus(_dafny.euclidian_division(d_0_ml_, 1099511627776), 256), _dafny.euclidian_modulus(_dafny.euclidian_division(d_0_ml_, 4294967296), 256), _dafny.euclidian_modulus(_dafny.euclidian_division(d_0_ml_, 16777216), 256), _dafny.euclidian_modulus(_dafny.euclidian_division(d_0_ml_, 65536), 256), _dafny.euclidian_modulus(_dafny.euclidian_division(d_0_ml_, 256), 256), _dafny.euclidian_modulus(d_0_ml_, 256)]))
        return ((d_1_withOne_) + (d_3_zeros_)) + (d_5_lenBytes_)

    @staticmethod
    def Ch64(e, f, g):
        return default__.Xor64(default__.And64(e, f), default__.And64(default__.Not64(e), g))

    @staticmethod
    def Maj64(a, b, c):
        return default__.Xor64(default__.Xor64(default__.And64(a, b), default__.And64(a, c)), default__.And64(b, c))

    @staticmethod
    def BigT0(a):
        return default__.Xor64(default__.Xor64(default__.RotR64(a, 28), default__.RotR64(a, 34)), default__.RotR64(a, 39))

    @staticmethod
    def BigT1(e):
        return default__.Xor64(default__.Xor64(default__.RotR64(e, 14), default__.RotR64(e, 18)), default__.RotR64(e, 41))

    @staticmethod
    def SigT0(x):
        return default__.Xor64(default__.Xor64(default__.RotR64(x, 1), default__.RotR64(x, 8)), (x) >> (7))

    @staticmethod
    def SigT1(x):
        return default__.Xor64(default__.Xor64(default__.RotR64(x, 19), default__.RotR64(x, 61)), (x) >> (6))

    @staticmethod
    def BuildW512(block):
        w: _dafny.Seq = _dafny.Seq({})
        d_0_ws_: _dafny.Array
        nw0_ = _dafny.Array(int(0), 80)
        d_0_ws_ = nw0_
        d_1_t_: int
        d_1_t_ = 0
        while (d_1_t_) < (16):
            (d_0_ws_)[(d_1_t_)] = default__.BE64(block, (d_1_t_) * (8))
            d_1_t_ = (d_1_t_) + (1)
        d_1_t_ = 16
        while (d_1_t_) < (80):
            (d_0_ws_)[(d_1_t_)] = ((((((default__.SigT1((d_0_ws_)[(d_1_t_) - (2)])) + ((d_0_ws_)[(d_1_t_) - (7)])) & ((1 << 64) - 1)) + (default__.SigT0((d_0_ws_)[(d_1_t_) - (15)]))) & ((1 << 64) - 1)) + ((d_0_ws_)[(d_1_t_) - (16)])) & ((1 << 64) - 1)
            d_1_t_ = (d_1_t_) + (1)
        w = _dafny.SeqWithoutIsStrInference((d_0_ws_)[::])
        return w

    @staticmethod
    def Sha512(msg):
        digest: _dafny.Seq = _dafny.Seq({})
        d_0_padded_: _dafny.Seq
        d_0_padded_ = default__.Pad128(msg)
        d_1_h0_: int
        d_1_h0_ = 7640891576956012808
        d_2_h1_: int
        d_2_h1_ = 13503953896175478587
        d_3_h2_: int
        d_3_h2_ = 4354685564936845355
        d_4_h3_: int
        d_4_h3_ = 11912009170470909681
        d_5_h4_: int
        d_5_h4_ = 5840696475078001361
        d_6_h5_: int
        d_6_h5_ = 11170449401992604703
        d_7_h6_: int
        d_7_h6_ = 2270897969802886507
        d_8_h7_: int
        d_8_h7_ = 6620516959819538809
        d_9_nblocks_: int
        d_9_nblocks_ = _dafny.euclidian_division(len(d_0_padded_), 128)
        d_10_bi_: int
        d_10_bi_ = 0
        while (d_10_bi_) < (d_9_nblocks_):
            d_11_start_: int
            d_11_start_ = (d_10_bi_) * (128)
            if ((d_11_start_) + (128)) <= (len(d_0_padded_)):
                d_12_block_: _dafny.Seq
                d_12_block_ = _dafny.SeqWithoutIsStrInference((d_0_padded_)[d_11_start_:(d_11_start_) + (128):])
                d_13_w_: _dafny.Seq
                out0_: _dafny.Seq
                out0_ = default__.BuildW512(d_12_block_)
                d_13_w_ = out0_
                d_14_a_: int
                d_14_a_ = d_1_h0_
                d_15_b_: int
                d_15_b_ = d_2_h1_
                d_16_c_: int
                d_16_c_ = d_3_h2_
                d_17_d_: int
                d_17_d_ = d_4_h3_
                d_18_e_: int
                d_18_e_ = d_5_h4_
                d_19_f_: int
                d_19_f_ = d_6_h5_
                d_20_g_: int
                d_20_g_ = d_7_h6_
                d_21_h_: int
                d_21_h_ = d_8_h7_
                d_22_t_: int
                d_22_t_ = 0
                while (d_22_t_) < (80):
                    d_23_t1_: int
                    d_23_t1_ = ((((((((d_21_h_) + (default__.BigT1(d_18_e_))) & ((1 << 64) - 1)) + (default__.Ch64(d_18_e_, d_19_f_, d_20_g_))) & ((1 << 64) - 1)) + ((default__.K512)[d_22_t_])) & ((1 << 64) - 1)) + ((d_13_w_)[d_22_t_])) & ((1 << 64) - 1)
                    d_24_t2_: int
                    d_24_t2_ = ((default__.BigT0(d_14_a_)) + (default__.Maj64(d_14_a_, d_15_b_, d_16_c_))) & ((1 << 64) - 1)
                    d_21_h_ = d_20_g_
                    d_20_g_ = d_19_f_
                    d_19_f_ = d_18_e_
                    d_18_e_ = ((d_17_d_) + (d_23_t1_)) & ((1 << 64) - 1)
                    d_17_d_ = d_16_c_
                    d_16_c_ = d_15_b_
                    d_15_b_ = d_14_a_
                    d_14_a_ = ((d_23_t1_) + (d_24_t2_)) & ((1 << 64) - 1)
                    d_22_t_ = (d_22_t_) + (1)
                d_1_h0_ = ((d_1_h0_) + (d_14_a_)) & ((1 << 64) - 1)
                d_2_h1_ = ((d_2_h1_) + (d_15_b_)) & ((1 << 64) - 1)
                d_3_h2_ = ((d_3_h2_) + (d_16_c_)) & ((1 << 64) - 1)
                d_4_h3_ = ((d_4_h3_) + (d_17_d_)) & ((1 << 64) - 1)
                d_5_h4_ = ((d_5_h4_) + (d_18_e_)) & ((1 << 64) - 1)
                d_6_h5_ = ((d_6_h5_) + (d_19_f_)) & ((1 << 64) - 1)
                d_7_h6_ = ((d_7_h6_) + (d_20_g_)) & ((1 << 64) - 1)
                d_8_h7_ = ((d_8_h7_) + (d_21_h_)) & ((1 << 64) - 1)
            d_10_bi_ = (d_10_bi_) + (1)
        digest = (((((((default__.Bv64ToBE(d_1_h0_)) + (default__.Bv64ToBE(d_2_h1_))) + (default__.Bv64ToBE(d_3_h2_))) + (default__.Bv64ToBE(d_4_h3_))) + (default__.Bv64ToBE(d_5_h4_))) + (default__.Bv64ToBE(d_6_h5_))) + (default__.Bv64ToBE(d_7_h6_))) + (default__.Bv64ToBE(d_8_h7_))
        return digest

    @_dafny.classproperty
    def K256(instance):
        return _dafny.SeqWithoutIsStrInference([1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298])
    @_dafny.classproperty
    def K512(instance):
        return _dafny.SeqWithoutIsStrInference([4794697086780616226, 8158064640168781261, 13096744586834688815, 16840607885511220156, 4131703408338449720, 6480981068601479193, 10538285296894168987, 12329834152419229976, 15566598209576043074, 1334009975649890238, 2608012711638119052, 6128411473006802146, 8268148722764581231, 9286055187155687089, 11230858885718282805, 13951009754708518548, 16472876342353939154, 17275323862435702243, 1135362057144423861, 2597628984639134821, 3308224258029322869, 5365058923640841347, 6679025012923562964, 8573033837759648693, 10970295158949994411, 12119686244451234320, 12683024718118986047, 13788192230050041572, 14330467153632333762, 15395433587784984357, 489312712824947311, 1452737877330783856, 2861767655752347644, 3322285676063803686, 5560940570517711597, 5996557281743188959, 7280758554555802590, 8532644243296465576, 9350256976987008742, 10552545826968843579, 11727347734174303076, 12113106623233404929, 14000437183269869457, 14369950271660146224, 15101387698204529176, 15463397548674623760, 17586052441742319658, 1182934255886127544, 1847814050463011016, 2177327727835720531, 2830643537854262169, 3796741975233480872, 4115178125766777443, 5681478168544905931, 6601373596472566643, 7507060721942968483, 8399075790359081724, 8693463985226723168, 9568029438360202098, 10144078919501101548, 10430055236837252648, 11840083180663258601, 13761210420658862357, 14299343276471374635, 14566680578165727644, 15097957966210449927, 16922976911328602910, 17689382322260857208, 500013540394364858, 748580250866718886, 1242879168328830382, 1977374033974150939, 2944078676154940804, 3659926193048069267, 4368137639120453308, 4836135668995329356, 5532061633213252278, 6448918945643986474, 6902733635092675308, 7801388544844847127])

class byte:
    def  __init__(self):
        pass

    @staticmethod
    def default():
        return int(0)
    def _Is(source__):
        return True
