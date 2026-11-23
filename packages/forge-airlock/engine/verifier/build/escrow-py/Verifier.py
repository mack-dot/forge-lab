import sys
from typing import Callable, Any, TypeVar, NamedTuple
from math import floor
from itertools import count

import module_ as module_
import _dafny as _dafny
import System_ as System_
import Sha as Sha
import Ed as Ed
import Model as Model

# Module: Verifier

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def Asc(s):
        return _dafny.SeqWithoutIsStrInference([_dafny.euclidian_modulus(ord((s)[d_0_i_]), 256) for d_0_i_ in range(len(s))])

    @staticmethod
    def Pow(b, n):
        d_0___accumulator_ = 1
        while True:
            with _dafny.label():
                if (n) == (0):
                    return (1) * (d_0___accumulator_)
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) * (b)
                    in0_ = b
                    in1_ = (n) - (1)
                    b = in0_
                    n = in1_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def LE(s, off, n):
        if (n) == (0):
            return 0
        elif True:
            return ((s)[off]) + ((256) * (default__.LE(s, (off) + (1), (n) - (1))))

    @staticmethod
    def Zeros(n):
        return _dafny.SeqWithoutIsStrInference([0 for d_0_i_ in range(n)])

    @staticmethod
    def HexDigit(v):
        if (v) < (10):
            return (48) + (v)
        elif True:
            return (87) + (v)

    @staticmethod
    def HexOf(b):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(b)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([default__.HexDigit(_dafny.euclidian_division((b)[0], 16)), default__.HexDigit(_dafny.euclidian_modulus((b)[0], 16))]))
                    in0_ = _dafny.SeqWithoutIsStrInference((b)[1::])
                    b = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def IsHexChar(c):
        d_0_v_ = c
        return ((((48) <= (d_0_v_)) and ((d_0_v_) <= (57))) or (((97) <= (d_0_v_)) and ((d_0_v_) <= (102)))) or (((65) <= (d_0_v_)) and ((d_0_v_) <= (70)))

    @staticmethod
    def LowerHex(c):
        d_0_v_ = c
        if ((65) <= (d_0_v_)) and ((d_0_v_) <= (70)):
            return (d_0_v_) + (32)
        elif True:
            return c

    @staticmethod
    def LowerHexSeq(s):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(s)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([default__.LowerHex((s)[0])]))
                    in0_ = _dafny.SeqWithoutIsStrInference((s)[1::])
                    s = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def ValidHex64(h):
        def lambda0_(forall_var_0_):
            d_0_i_: int = forall_var_0_
            return not (((0) <= (d_0_i_)) and ((d_0_i_) < (len(h)))) or (default__.IsHexChar((h)[d_0_i_]))

        return ((len(h)) == (64)) and (_dafny.quantifier(_dafny.IntegerRange(0, len(h)), True, lambda0_))

    @staticmethod
    def SealOk(rec):
        ok: bool = False
        d_0_h_: _dafny.Seq
        out0_: _dafny.Seq
        out0_ = Sha.default__.Sha256(_dafny.SeqWithoutIsStrInference((rec)[0:96:]))
        d_0_h_ = out0_
        ok = (d_0_h_) == (_dafny.SeqWithoutIsStrInference((rec)[96:128:]))
        return ok

    @staticmethod
    def WholeHash(rec):
        h: _dafny.Seq = _dafny.Seq({})
        out0_: _dafny.Seq
        out0_ = Sha.default__.Sha256(rec)
        h = out0_
        return h

    @staticmethod
    def VerifyCLI(log, manifestPresent, manifest, pubPresent, pubA, pubB, tapePresent, tape, obsPresent, observedNow, tipPresent, expectTip, maxRecords):
        r: Res = Res.default()()
        d_0_records_: int
        d_0_records_ = _dafny.euclidian_division(len(log), 128)
        d_1_tornBytes_: int
        d_1_tornBytes_ = _dafny.euclidian_modulus(len(log), 128)
        r = Res_Res(default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "UNVERIFIABLE_INTERNAL"))), 3, d_0_records_, d_1_tornBytes_, True, 0, 0, 0, 0, _dafny.SeqWithoutIsStrInference([]), 0, False)
        if (not(manifestPresent)) or (not(pubPresent)):
            d_2_dt__update__tmp_h0_ = r
            d_3_dt__update_hexitCode_h0_ = 3
            d_4_dt__update_hverdict_h0_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "UNVERIFIABLE_USAGE")))
            r = Res_Res(d_4_dt__update_hverdict_h0_, d_3_dt__update_hexitCode_h0_, (d_2_dt__update__tmp_h0_).records, (d_2_dt__update__tmp_h0_).tornBytes, (d_2_dt__update__tmp_h0_).failNull, (d_2_dt__update__tmp_h0_).failIndex, (d_2_dt__update__tmp_h0_).gross, (d_2_dt__update__tmp_h0_).sellerPayout, (d_2_dt__update__tmp_h0_).buyerRefund, (d_2_dt__update__tmp_h0_).tip, (d_2_dt__update__tmp_h0_).epoch, (d_2_dt__update__tmp_h0_).expiryGate)
            return r
        if ((len(pubA)) != (32)) or ((len(pubB)) != (32)):
            d_5_dt__update__tmp_h1_ = r
            d_6_dt__update_hexitCode_h1_ = 3
            d_7_dt__update_hverdict_h1_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "UNVERIFIABLE_USAGE")))
            r = Res_Res(d_7_dt__update_hverdict_h1_, d_6_dt__update_hexitCode_h1_, (d_5_dt__update__tmp_h1_).records, (d_5_dt__update__tmp_h1_).tornBytes, (d_5_dt__update__tmp_h1_).failNull, (d_5_dt__update__tmp_h1_).failIndex, (d_5_dt__update__tmp_h1_).gross, (d_5_dt__update__tmp_h1_).sellerPayout, (d_5_dt__update__tmp_h1_).buyerRefund, (d_5_dt__update__tmp_h1_).tip, (d_5_dt__update__tmp_h1_).epoch, (d_5_dt__update__tmp_h1_).expiryGate)
            return r
        if (len(log)) == (0):
            d_8_dt__update__tmp_h2_ = r
            d_9_dt__update_hexitCode_h2_ = 3
            d_10_dt__update_hverdict_h2_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "UNVERIFIABLE_EMPTY")))
            r = Res_Res(d_10_dt__update_hverdict_h2_, d_9_dt__update_hexitCode_h2_, (d_8_dt__update__tmp_h2_).records, (d_8_dt__update__tmp_h2_).tornBytes, (d_8_dt__update__tmp_h2_).failNull, (d_8_dt__update__tmp_h2_).failIndex, (d_8_dt__update__tmp_h2_).gross, (d_8_dt__update__tmp_h2_).sellerPayout, (d_8_dt__update__tmp_h2_).buyerRefund, (d_8_dt__update__tmp_h2_).tip, (d_8_dt__update__tmp_h2_).epoch, (d_8_dt__update__tmp_h2_).expiryGate)
            return r
        if (d_0_records_) == (0):
            d_11_dt__update__tmp_h3_ = r
            d_12_dt__update_hexitCode_h3_ = 3
            d_13_dt__update_hverdict_h3_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "UNVERIFIABLE_NO_RECORD")))
            r = Res_Res(d_13_dt__update_hverdict_h3_, d_12_dt__update_hexitCode_h3_, (d_11_dt__update__tmp_h3_).records, (d_11_dt__update__tmp_h3_).tornBytes, (d_11_dt__update__tmp_h3_).failNull, (d_11_dt__update__tmp_h3_).failIndex, (d_11_dt__update__tmp_h3_).gross, (d_11_dt__update__tmp_h3_).sellerPayout, (d_11_dt__update__tmp_h3_).buyerRefund, (d_11_dt__update__tmp_h3_).tip, (d_11_dt__update__tmp_h3_).epoch, (d_11_dt__update__tmp_h3_).expiryGate)
            return r
        if (d_0_records_) > (maxRecords):
            d_14_dt__update__tmp_h4_ = r
            d_15_dt__update_hexitCode_h4_ = 3
            d_16_dt__update_hverdict_h4_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "UNVERIFIABLE_TOO_LARGE")))
            r = Res_Res(d_16_dt__update_hverdict_h4_, d_15_dt__update_hexitCode_h4_, (d_14_dt__update__tmp_h4_).records, (d_14_dt__update__tmp_h4_).tornBytes, (d_14_dt__update__tmp_h4_).failNull, (d_14_dt__update__tmp_h4_).failIndex, (d_14_dt__update__tmp_h4_).gross, (d_14_dt__update__tmp_h4_).sellerPayout, (d_14_dt__update__tmp_h4_).buyerRefund, (d_14_dt__update__tmp_h4_).tip, (d_14_dt__update__tmp_h4_).epoch, (d_14_dt__update__tmp_h4_).expiryGate)
            return r
        if ((d_0_records_) >= (2)) and (not(obsPresent)):
            d_17_dt__update__tmp_h5_ = r
            d_18_dt__update_hexitCode_h5_ = 3
            d_19_dt__update_hverdict_h5_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "UNVERIFIABLE_USAGE")))
            r = Res_Res(d_19_dt__update_hverdict_h5_, d_18_dt__update_hexitCode_h5_, (d_17_dt__update__tmp_h5_).records, (d_17_dt__update__tmp_h5_).tornBytes, (d_17_dt__update__tmp_h5_).failNull, (d_17_dt__update__tmp_h5_).failIndex, (d_17_dt__update__tmp_h5_).gross, (d_17_dt__update__tmp_h5_).sellerPayout, (d_17_dt__update__tmp_h5_).buyerRefund, (d_17_dt__update__tmp_h5_).tip, (d_17_dt__update__tmp_h5_).epoch, (d_17_dt__update__tmp_h5_).expiryGate)
            return r
        if (tipPresent) and (not(default__.ValidHex64(expectTip))):
            d_20_dt__update__tmp_h6_ = r
            d_21_dt__update_hexitCode_h6_ = 3
            d_22_dt__update_hverdict_h6_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "UNVERIFIABLE_USAGE")))
            r = Res_Res(d_22_dt__update_hverdict_h6_, d_21_dt__update_hexitCode_h6_, (d_20_dt__update__tmp_h6_).records, (d_20_dt__update__tmp_h6_).tornBytes, (d_20_dt__update__tmp_h6_).failNull, (d_20_dt__update__tmp_h6_).failIndex, (d_20_dt__update__tmp_h6_).gross, (d_20_dt__update__tmp_h6_).sellerPayout, (d_20_dt__update__tmp_h6_).buyerRefund, (d_20_dt__update__tmp_h6_).tip, (d_20_dt__update__tmp_h6_).epoch, (d_20_dt__update__tmp_h6_).expiryGate)
            return r
        d_23_g_: _dafny.Seq
        d_23_g_ = _dafny.SeqWithoutIsStrInference((log)[0:128:])
        if (_dafny.SeqWithoutIsStrInference((d_23_g_)[0:3:])) != (default__.MAGIC):
            d_24_dt__update__tmp_h7_ = r
            d_25_dt__update_hfailIndex_h0_ = 0
            d_26_dt__update_hfailNull_h0_ = False
            d_27_dt__update_hexitCode_h7_ = 1
            d_28_dt__update_hverdict_h7_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_MALFORMED_RECORD")))
            r = Res_Res(d_28_dt__update_hverdict_h7_, d_27_dt__update_hexitCode_h7_, (d_24_dt__update__tmp_h7_).records, (d_24_dt__update__tmp_h7_).tornBytes, d_26_dt__update_hfailNull_h0_, d_25_dt__update_hfailIndex_h0_, (d_24_dt__update__tmp_h7_).gross, (d_24_dt__update__tmp_h7_).sellerPayout, (d_24_dt__update__tmp_h7_).buyerRefund, (d_24_dt__update__tmp_h7_).tip, (d_24_dt__update__tmp_h7_).epoch, (d_24_dt__update__tmp_h7_).expiryGate)
            return r
        if ((d_23_g_)[3]) != (2):
            d_29_dt__update__tmp_h8_ = r
            d_30_dt__update_hfailIndex_h1_ = 0
            d_31_dt__update_hfailNull_h1_ = False
            d_32_dt__update_hexitCode_h8_ = 1
            d_33_dt__update_hverdict_h8_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_MALFORMED_RECORD")))
            r = Res_Res(d_33_dt__update_hverdict_h8_, d_32_dt__update_hexitCode_h8_, (d_29_dt__update__tmp_h8_).records, (d_29_dt__update__tmp_h8_).tornBytes, d_31_dt__update_hfailNull_h1_, d_30_dt__update_hfailIndex_h1_, (d_29_dt__update__tmp_h8_).gross, (d_29_dt__update__tmp_h8_).sellerPayout, (d_29_dt__update__tmp_h8_).buyerRefund, (d_29_dt__update__tmp_h8_).tip, (d_29_dt__update__tmp_h8_).epoch, (d_29_dt__update__tmp_h8_).expiryGate)
            return r
        if (_dafny.SeqWithoutIsStrInference((d_23_g_)[6:8:])) != (default__.Zeros(2)):
            d_34_dt__update__tmp_h9_ = r
            d_35_dt__update_hfailIndex_h2_ = 0
            d_36_dt__update_hfailNull_h2_ = False
            d_37_dt__update_hexitCode_h9_ = 1
            d_38_dt__update_hverdict_h9_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_MALFORMED_RECORD")))
            r = Res_Res(d_38_dt__update_hverdict_h9_, d_37_dt__update_hexitCode_h9_, (d_34_dt__update__tmp_h9_).records, (d_34_dt__update__tmp_h9_).tornBytes, d_36_dt__update_hfailNull_h2_, d_35_dt__update_hfailIndex_h2_, (d_34_dt__update__tmp_h9_).gross, (d_34_dt__update__tmp_h9_).sellerPayout, (d_34_dt__update__tmp_h9_).buyerRefund, (d_34_dt__update__tmp_h9_).tip, (d_34_dt__update__tmp_h9_).epoch, (d_34_dt__update__tmp_h9_).expiryGate)
            return r
        if ((d_23_g_)[5]) != (71):
            d_39_dt__update__tmp_h10_ = r
            d_40_dt__update_hfailIndex_h3_ = 0
            d_41_dt__update_hfailNull_h3_ = False
            d_42_dt__update_hexitCode_h10_ = 1
            d_43_dt__update_hverdict_h10_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_BAD_GENESIS")))
            r = Res_Res(d_43_dt__update_hverdict_h10_, d_42_dt__update_hexitCode_h10_, (d_39_dt__update__tmp_h10_).records, (d_39_dt__update__tmp_h10_).tornBytes, d_41_dt__update_hfailNull_h3_, d_40_dt__update_hfailIndex_h3_, (d_39_dt__update__tmp_h10_).gross, (d_39_dt__update__tmp_h10_).sellerPayout, (d_39_dt__update__tmp_h10_).buyerRefund, (d_39_dt__update__tmp_h10_).tip, (d_39_dt__update__tmp_h10_).epoch, (d_39_dt__update__tmp_h10_).expiryGate)
            return r
        if (default__.LE(d_23_g_, 8, 8)) != (0):
            d_44_dt__update__tmp_h11_ = r
            d_45_dt__update_hfailIndex_h4_ = 0
            d_46_dt__update_hfailNull_h4_ = False
            d_47_dt__update_hexitCode_h11_ = 1
            d_48_dt__update_hverdict_h11_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_SEQ_MISMATCH")))
            r = Res_Res(d_48_dt__update_hverdict_h11_, d_47_dt__update_hexitCode_h11_, (d_44_dt__update__tmp_h11_).records, (d_44_dt__update__tmp_h11_).tornBytes, d_46_dt__update_hfailNull_h4_, d_45_dt__update_hfailIndex_h4_, (d_44_dt__update__tmp_h11_).gross, (d_44_dt__update__tmp_h11_).sellerPayout, (d_44_dt__update__tmp_h11_).buyerRefund, (d_44_dt__update__tmp_h11_).tip, (d_44_dt__update__tmp_h11_).epoch, (d_44_dt__update__tmp_h11_).expiryGate)
            return r
        if (_dafny.SeqWithoutIsStrInference((d_23_g_)[16:48:])) != (default__.Zeros(32)):
            d_49_dt__update__tmp_h12_ = r
            d_50_dt__update_hfailIndex_h5_ = 0
            d_51_dt__update_hfailNull_h5_ = False
            d_52_dt__update_hexitCode_h12_ = 1
            d_53_dt__update_hverdict_h12_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_BAD_GENESIS")))
            r = Res_Res(d_53_dt__update_hverdict_h12_, d_52_dt__update_hexitCode_h12_, (d_49_dt__update__tmp_h12_).records, (d_49_dt__update__tmp_h12_).tornBytes, d_51_dt__update_hfailNull_h5_, d_50_dt__update_hfailIndex_h5_, (d_49_dt__update__tmp_h12_).gross, (d_49_dt__update__tmp_h12_).sellerPayout, (d_49_dt__update__tmp_h12_).buyerRefund, (d_49_dt__update__tmp_h12_).tip, (d_49_dt__update__tmp_h12_).epoch, (d_49_dt__update__tmp_h12_).expiryGate)
            return r
        if ((d_23_g_)[4]) != (2):
            d_54_dt__update__tmp_h13_ = r
            d_55_dt__update_hfailIndex_h6_ = 0
            d_56_dt__update_hfailNull_h6_ = False
            d_57_dt__update_hexitCode_h13_ = 1
            d_58_dt__update_hverdict_h13_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_BAD_DOMAIN")))
            r = Res_Res(d_58_dt__update_hverdict_h13_, d_57_dt__update_hexitCode_h13_, (d_54_dt__update__tmp_h13_).records, (d_54_dt__update__tmp_h13_).tornBytes, d_56_dt__update_hfailNull_h6_, d_55_dt__update_hfailIndex_h6_, (d_54_dt__update__tmp_h13_).gross, (d_54_dt__update__tmp_h13_).sellerPayout, (d_54_dt__update__tmp_h13_).buyerRefund, (d_54_dt__update__tmp_h13_).tip, (d_54_dt__update__tmp_h13_).epoch, (d_54_dt__update__tmp_h13_).expiryGate)
            return r
        d_59_gseal_: bool
        out0_: bool
        out0_ = default__.SealOk(d_23_g_)
        d_59_gseal_ = out0_
        if not(d_59_gseal_):
            d_60_dt__update__tmp_h14_ = r
            d_61_dt__update_hfailIndex_h7_ = 0
            d_62_dt__update_hfailNull_h7_ = False
            d_63_dt__update_hexitCode_h14_ = 1
            d_64_dt__update_hverdict_h14_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_BAD_SEAL")))
            r = Res_Res(d_64_dt__update_hverdict_h14_, d_63_dt__update_hexitCode_h14_, (d_60_dt__update__tmp_h14_).records, (d_60_dt__update__tmp_h14_).tornBytes, d_62_dt__update_hfailNull_h7_, d_61_dt__update_hfailIndex_h7_, (d_60_dt__update__tmp_h14_).gross, (d_60_dt__update__tmp_h14_).sellerPayout, (d_60_dt__update__tmp_h14_).buyerRefund, (d_60_dt__update__tmp_h14_).tip, (d_60_dt__update__tmp_h14_).epoch, (d_60_dt__update__tmp_h14_).expiryGate)
            return r
        d_65_cap_: int
        d_65_cap_ = default__.LE(d_23_g_, 48, 8)
        d_66_expiresAt_: int
        d_66_expiresAt_ = default__.LE(d_23_g_, 56, 8)
        if (d_65_cap_) > (default__.MONEY__MAX):
            d_67_dt__update__tmp_h15_ = r
            d_68_dt__update_hfailIndex_h8_ = 0
            d_69_dt__update_hfailNull_h8_ = False
            d_70_dt__update_hexitCode_h15_ = 1
            d_71_dt__update_hverdict_h15_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_AMOUNT_NOT_MONEY")))
            r = Res_Res(d_71_dt__update_hverdict_h15_, d_70_dt__update_hexitCode_h15_, (d_67_dt__update__tmp_h15_).records, (d_67_dt__update__tmp_h15_).tornBytes, d_69_dt__update_hfailNull_h8_, d_68_dt__update_hfailIndex_h8_, (d_67_dt__update__tmp_h15_).gross, (d_67_dt__update__tmp_h15_).sellerPayout, (d_67_dt__update__tmp_h15_).buyerRefund, (d_67_dt__update__tmp_h15_).tip, (d_67_dt__update__tmp_h15_).epoch, (d_67_dt__update__tmp_h15_).expiryGate)
            return r
        d_72_manifestHash_: _dafny.Seq
        d_72_manifestHash_ = _dafny.SeqWithoutIsStrInference((d_23_g_)[64:96:])
        if (len(manifest)) != (176):
            d_73_dt__update__tmp_h16_ = r
            d_74_dt__update_hfailIndex_h9_ = 0
            d_75_dt__update_hfailNull_h9_ = False
            d_76_dt__update_hexitCode_h16_ = 1
            d_77_dt__update_hverdict_h16_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_BAD_GENESIS")))
            r = Res_Res(d_77_dt__update_hverdict_h16_, d_76_dt__update_hexitCode_h16_, (d_73_dt__update__tmp_h16_).records, (d_73_dt__update__tmp_h16_).tornBytes, d_75_dt__update_hfailNull_h9_, d_74_dt__update_hfailIndex_h9_, (d_73_dt__update__tmp_h16_).gross, (d_73_dt__update__tmp_h16_).sellerPayout, (d_73_dt__update__tmp_h16_).buyerRefund, (d_73_dt__update__tmp_h16_).tip, (d_73_dt__update__tmp_h16_).epoch, (d_73_dt__update__tmp_h16_).expiryGate)
            return r
        d_78_mh_: _dafny.Seq
        out1_: _dafny.Seq
        out1_ = Sha.default__.Sha256(manifest)
        d_78_mh_ = out1_
        if (d_78_mh_) != (d_72_manifestHash_):
            d_79_dt__update__tmp_h17_ = r
            d_80_dt__update_hfailIndex_h10_ = 0
            d_81_dt__update_hfailNull_h10_ = False
            d_82_dt__update_hexitCode_h17_ = 1
            d_83_dt__update_hverdict_h17_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_BAD_GENESIS")))
            r = Res_Res(d_83_dt__update_hverdict_h17_, d_82_dt__update_hexitCode_h17_, (d_79_dt__update__tmp_h17_).records, (d_79_dt__update__tmp_h17_).tornBytes, d_81_dt__update_hfailNull_h10_, d_80_dt__update_hfailIndex_h10_, (d_79_dt__update__tmp_h17_).gross, (d_79_dt__update__tmp_h17_).sellerPayout, (d_79_dt__update__tmp_h17_).buyerRefund, (d_79_dt__update__tmp_h17_).tip, (d_79_dt__update__tmp_h17_).epoch, (d_79_dt__update__tmp_h17_).expiryGate)
            return r
        d_84_mCap_: int
        d_84_mCap_ = default__.LE(manifest, 160, 8)
        d_85_mExp_: int
        d_85_mExp_ = default__.LE(manifest, 168, 8)
        if ((d_84_mCap_) != (d_65_cap_)) or ((d_85_mExp_) != (d_66_expiresAt_)):
            d_86_dt__update__tmp_h18_ = r
            d_87_dt__update_hfailIndex_h11_ = 0
            d_88_dt__update_hfailNull_h11_ = False
            d_89_dt__update_hexitCode_h18_ = 1
            d_90_dt__update_hverdict_h18_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_BAD_GENESIS")))
            r = Res_Res(d_90_dt__update_hverdict_h18_, d_89_dt__update_hexitCode_h18_, (d_86_dt__update__tmp_h18_).records, (d_86_dt__update__tmp_h18_).tornBytes, d_88_dt__update_hfailNull_h11_, d_87_dt__update_hfailIndex_h11_, (d_86_dt__update__tmp_h18_).gross, (d_86_dt__update__tmp_h18_).sellerPayout, (d_86_dt__update__tmp_h18_).buyerRefund, (d_86_dt__update__tmp_h18_).tip, (d_86_dt__update__tmp_h18_).epoch, (d_86_dt__update__tmp_h18_).expiryGate)
            return r
        d_91_dealId_: _dafny.Seq
        d_91_dealId_ = _dafny.SeqWithoutIsStrInference((manifest)[0:32:])
        d_92_escrowId_: _dafny.Seq
        d_92_escrowId_ = _dafny.SeqWithoutIsStrInference((manifest)[128:160:])
        if ((d_91_dealId_) == (default__.Zeros(32))) or ((d_92_escrowId_) == (default__.Zeros(32))):
            d_93_dt__update__tmp_h19_ = r
            d_94_dt__update_hfailIndex_h12_ = 0
            d_95_dt__update_hfailNull_h12_ = False
            d_96_dt__update_hexitCode_h19_ = 1
            d_97_dt__update_hverdict_h19_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_EMPTY_ID")))
            r = Res_Res(d_97_dt__update_hverdict_h19_, d_96_dt__update_hexitCode_h19_, (d_93_dt__update__tmp_h19_).records, (d_93_dt__update__tmp_h19_).tornBytes, d_95_dt__update_hfailNull_h12_, d_94_dt__update_hfailIndex_h12_, (d_93_dt__update__tmp_h19_).gross, (d_93_dt__update__tmp_h19_).sellerPayout, (d_93_dt__update__tmp_h19_).buyerRefund, (d_93_dt__update__tmp_h19_).tip, (d_93_dt__update__tmp_h19_).epoch, (d_93_dt__update__tmp_h19_).expiryGate)
            return r
        d_98_keyA_: _dafny.Seq
        d_98_keyA_ = _dafny.SeqWithoutIsStrInference((manifest)[32:64:])
        d_99_keyB_: _dafny.Seq
        d_99_keyB_ = _dafny.SeqWithoutIsStrInference((manifest)[64:96:])
        d_100_vkA_: int
        out2_: int
        out2_ = Ed.default__.ValidateKey(d_98_keyA_)
        d_100_vkA_ = out2_
        d_101_vkB_: int
        out3_: int
        out3_ = Ed.default__.ValidateKey(d_99_keyB_)
        d_101_vkB_ = out3_
        if ((d_100_vkA_) != (0)) or ((d_101_vkB_) != (0)):
            d_102_dt__update__tmp_h20_ = r
            d_103_dt__update_hfailIndex_h13_ = 0
            d_104_dt__update_hfailNull_h13_ = False
            d_105_dt__update_hexitCode_h20_ = 1
            d_106_dt__update_hverdict_h20_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_BAD_KEY")))
            r = Res_Res(d_106_dt__update_hverdict_h20_, d_105_dt__update_hexitCode_h20_, (d_102_dt__update__tmp_h20_).records, (d_102_dt__update__tmp_h20_).tornBytes, d_104_dt__update_hfailNull_h13_, d_103_dt__update_hfailIndex_h13_, (d_102_dt__update__tmp_h20_).gross, (d_102_dt__update__tmp_h20_).sellerPayout, (d_102_dt__update__tmp_h20_).buyerRefund, (d_102_dt__update__tmp_h20_).tip, (d_102_dt__update__tmp_h20_).epoch, (d_102_dt__update__tmp_h20_).expiryGate)
            return r
        if ((pubA) != (d_98_keyA_)) or ((pubB) != (d_99_keyB_)):
            d_107_dt__update__tmp_h21_ = r
            d_108_dt__update_hfailIndex_h14_ = 0
            d_109_dt__update_hfailNull_h14_ = False
            d_110_dt__update_hexitCode_h21_ = 1
            d_111_dt__update_hverdict_h21_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_KEY_MISMATCH")))
            r = Res_Res(d_111_dt__update_hverdict_h21_, d_110_dt__update_hexitCode_h21_, (d_107_dt__update__tmp_h21_).records, (d_107_dt__update__tmp_h21_).tornBytes, d_109_dt__update_hfailNull_h14_, d_108_dt__update_hfailIndex_h14_, (d_107_dt__update__tmp_h21_).gross, (d_107_dt__update__tmp_h21_).sellerPayout, (d_107_dt__update__tmp_h21_).buyerRefund, (d_107_dt__update__tmp_h21_).tip, (d_107_dt__update__tmp_h21_).epoch, (d_107_dt__update__tmp_h21_).expiryGate)
            return r
        if tapePresent:
            d_112_gseal32_: _dafny.Seq
            d_112_gseal32_ = _dafny.SeqWithoutIsStrInference((d_23_g_)[96:128:])
            if (len(tape)) < (128):
                d_113_dt__update__tmp_h22_ = r
                d_114_dt__update_hfailIndex_h15_ = 0
                d_115_dt__update_hfailNull_h15_ = False
                d_116_dt__update_hexitCode_h22_ = 1
                d_117_dt__update_hverdict_h22_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_BAD_SIGNATURE")))
                r = Res_Res(d_117_dt__update_hverdict_h22_, d_116_dt__update_hexitCode_h22_, (d_113_dt__update__tmp_h22_).records, (d_113_dt__update__tmp_h22_).tornBytes, d_115_dt__update_hfailNull_h15_, d_114_dt__update_hfailIndex_h15_, (d_113_dt__update__tmp_h22_).gross, (d_113_dt__update__tmp_h22_).sellerPayout, (d_113_dt__update__tmp_h22_).buyerRefund, (d_113_dt__update__tmp_h22_).tip, (d_113_dt__update__tmp_h22_).epoch, (d_113_dt__update__tmp_h22_).expiryGate)
                return r
            d_118_sA_: _dafny.Seq
            d_118_sA_ = _dafny.SeqWithoutIsStrInference((tape)[0:64:])
            d_119_sB_: _dafny.Seq
            d_119_sB_ = _dafny.SeqWithoutIsStrInference((tape)[64:128:])
            d_120_rA_: int
            out4_: int
            out4_ = Ed.default__.VerifyStrict(d_98_keyA_, d_118_sA_, d_112_gseal32_)
            d_120_rA_ = out4_
            d_121_rB_: int
            out5_: int
            out5_ = Ed.default__.VerifyStrict(d_99_keyB_, d_119_sB_, d_112_gseal32_)
            d_121_rB_ = out5_
            if ((d_120_rA_) != (0)) or ((d_121_rB_) != (0)):
                d_122_dt__update__tmp_h23_ = r
                d_123_dt__update_hfailIndex_h16_ = 0
                d_124_dt__update_hfailNull_h16_ = False
                d_125_dt__update_hexitCode_h23_ = 1
                d_126_dt__update_hverdict_h23_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_BAD_SIGNATURE")))
                r = Res_Res(d_126_dt__update_hverdict_h23_, d_125_dt__update_hexitCode_h23_, (d_122_dt__update__tmp_h23_).records, (d_122_dt__update__tmp_h23_).tornBytes, d_124_dt__update_hfailNull_h16_, d_123_dt__update_hfailIndex_h16_, (d_122_dt__update__tmp_h23_).gross, (d_122_dt__update__tmp_h23_).sellerPayout, (d_122_dt__update__tmp_h23_).buyerRefund, (d_122_dt__update__tmp_h23_).tip, (d_122_dt__update__tmp_h23_).epoch, (d_122_dt__update__tmp_h23_).expiryGate)
                return r
        d_127_gross_: int
        d_127_gross_ = 0
        d_128_settled_: _dafny.Set
        d_128_settled_ = _dafny.Set({})
        d_129_tsPrev_: int
        d_129_tsPrev_ = 0
        d_130_tipHash_: _dafny.Seq
        d_130_tipHash_ = d_23_g_
        d_131_th_: _dafny.Seq
        out6_: _dafny.Seq
        out6_ = default__.WholeHash(d_23_g_)
        d_131_th_ = out6_
        d_130_tipHash_ = d_131_th_
        d_132_expiryEvaluated_: bool
        d_132_expiryEvaluated_ = False
        d_133_i_: int
        d_133_i_ = 1
        while (d_133_i_) < (d_0_records_):
            d_134_rec_: _dafny.Seq
            d_134_rec_ = _dafny.SeqWithoutIsStrInference((log)[(d_133_i_) * (128):((d_133_i_) * (128)) + (128):])
            if (_dafny.SeqWithoutIsStrInference((d_134_rec_)[0:3:])) != (default__.MAGIC):
                d_135_dt__update__tmp_h24_ = r
                d_136_dt__update_hfailIndex_h17_ = d_133_i_
                d_137_dt__update_hfailNull_h17_ = False
                d_138_dt__update_hexitCode_h24_ = 1
                d_139_dt__update_hverdict_h24_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_MALFORMED_RECORD")))
                r = Res_Res(d_139_dt__update_hverdict_h24_, d_138_dt__update_hexitCode_h24_, (d_135_dt__update__tmp_h24_).records, (d_135_dt__update__tmp_h24_).tornBytes, d_137_dt__update_hfailNull_h17_, d_136_dt__update_hfailIndex_h17_, (d_135_dt__update__tmp_h24_).gross, (d_135_dt__update__tmp_h24_).sellerPayout, (d_135_dt__update__tmp_h24_).buyerRefund, (d_135_dt__update__tmp_h24_).tip, (d_135_dt__update__tmp_h24_).epoch, (d_135_dt__update__tmp_h24_).expiryGate)
                return r
            if ((d_134_rec_)[3]) != (2):
                d_140_dt__update__tmp_h25_ = r
                d_141_dt__update_hfailIndex_h18_ = d_133_i_
                d_142_dt__update_hfailNull_h18_ = False
                d_143_dt__update_hexitCode_h25_ = 1
                d_144_dt__update_hverdict_h25_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_MALFORMED_RECORD")))
                r = Res_Res(d_144_dt__update_hverdict_h25_, d_143_dt__update_hexitCode_h25_, (d_140_dt__update__tmp_h25_).records, (d_140_dt__update__tmp_h25_).tornBytes, d_142_dt__update_hfailNull_h18_, d_141_dt__update_hfailIndex_h18_, (d_140_dt__update__tmp_h25_).gross, (d_140_dt__update__tmp_h25_).sellerPayout, (d_140_dt__update__tmp_h25_).buyerRefund, (d_140_dt__update__tmp_h25_).tip, (d_140_dt__update__tmp_h25_).epoch, (d_140_dt__update__tmp_h25_).expiryGate)
                return r
            if ((d_134_rec_)[4]) != (2):
                d_145_dt__update__tmp_h26_ = r
                d_146_dt__update_hfailIndex_h19_ = d_133_i_
                d_147_dt__update_hfailNull_h19_ = False
                d_148_dt__update_hexitCode_h26_ = 1
                d_149_dt__update_hverdict_h26_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_BAD_DOMAIN")))
                r = Res_Res(d_149_dt__update_hverdict_h26_, d_148_dt__update_hexitCode_h26_, (d_145_dt__update__tmp_h26_).records, (d_145_dt__update__tmp_h26_).tornBytes, d_147_dt__update_hfailNull_h19_, d_146_dt__update_hfailIndex_h19_, (d_145_dt__update__tmp_h26_).gross, (d_145_dt__update__tmp_h26_).sellerPayout, (d_145_dt__update__tmp_h26_).buyerRefund, (d_145_dt__update__tmp_h26_).tip, (d_145_dt__update__tmp_h26_).epoch, (d_145_dt__update__tmp_h26_).expiryGate)
                return r
            if ((d_134_rec_)[5]) != (83):
                d_150_dt__update__tmp_h27_ = r
                d_151_dt__update_hfailIndex_h20_ = d_133_i_
                d_152_dt__update_hfailNull_h20_ = False
                d_153_dt__update_hexitCode_h27_ = 1
                d_154_dt__update_hverdict_h27_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_MALFORMED_RECORD")))
                r = Res_Res(d_154_dt__update_hverdict_h27_, d_153_dt__update_hexitCode_h27_, (d_150_dt__update__tmp_h27_).records, (d_150_dt__update__tmp_h27_).tornBytes, d_152_dt__update_hfailNull_h20_, d_151_dt__update_hfailIndex_h20_, (d_150_dt__update__tmp_h27_).gross, (d_150_dt__update__tmp_h27_).sellerPayout, (d_150_dt__update__tmp_h27_).buyerRefund, (d_150_dt__update__tmp_h27_).tip, (d_150_dt__update__tmp_h27_).epoch, (d_150_dt__update__tmp_h27_).expiryGate)
                return r
            if (_dafny.SeqWithoutIsStrInference((d_134_rec_)[6:8:])) != (default__.Zeros(2)):
                d_155_dt__update__tmp_h28_ = r
                d_156_dt__update_hfailIndex_h21_ = d_133_i_
                d_157_dt__update_hfailNull_h21_ = False
                d_158_dt__update_hexitCode_h28_ = 1
                d_159_dt__update_hverdict_h28_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_MALFORMED_RECORD")))
                r = Res_Res(d_159_dt__update_hverdict_h28_, d_158_dt__update_hexitCode_h28_, (d_155_dt__update__tmp_h28_).records, (d_155_dt__update__tmp_h28_).tornBytes, d_157_dt__update_hfailNull_h21_, d_156_dt__update_hfailIndex_h21_, (d_155_dt__update__tmp_h28_).gross, (d_155_dt__update__tmp_h28_).sellerPayout, (d_155_dt__update__tmp_h28_).buyerRefund, (d_155_dt__update__tmp_h28_).tip, (d_155_dt__update__tmp_h28_).epoch, (d_155_dt__update__tmp_h28_).expiryGate)
                return r
            if (_dafny.SeqWithoutIsStrInference((d_134_rec_)[88:96:])) != (default__.Zeros(8)):
                d_160_dt__update__tmp_h29_ = r
                d_161_dt__update_hfailIndex_h22_ = d_133_i_
                d_162_dt__update_hfailNull_h22_ = False
                d_163_dt__update_hexitCode_h29_ = 1
                d_164_dt__update_hverdict_h29_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_MALFORMED_RECORD")))
                r = Res_Res(d_164_dt__update_hverdict_h29_, d_163_dt__update_hexitCode_h29_, (d_160_dt__update__tmp_h29_).records, (d_160_dt__update__tmp_h29_).tornBytes, d_162_dt__update_hfailNull_h22_, d_161_dt__update_hfailIndex_h22_, (d_160_dt__update__tmp_h29_).gross, (d_160_dt__update__tmp_h29_).sellerPayout, (d_160_dt__update__tmp_h29_).buyerRefund, (d_160_dt__update__tmp_h29_).tip, (d_160_dt__update__tmp_h29_).epoch, (d_160_dt__update__tmp_h29_).expiryGate)
                return r
            if (default__.LE(d_134_rec_, 8, 8)) != (d_133_i_):
                d_165_dt__update__tmp_h30_ = r
                d_166_dt__update_hfailIndex_h23_ = d_133_i_
                d_167_dt__update_hfailNull_h23_ = False
                d_168_dt__update_hexitCode_h30_ = 1
                d_169_dt__update_hverdict_h30_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_SEQ_MISMATCH")))
                r = Res_Res(d_169_dt__update_hverdict_h30_, d_168_dt__update_hexitCode_h30_, (d_165_dt__update__tmp_h30_).records, (d_165_dt__update__tmp_h30_).tornBytes, d_167_dt__update_hfailNull_h23_, d_166_dt__update_hfailIndex_h23_, (d_165_dt__update__tmp_h30_).gross, (d_165_dt__update__tmp_h30_).sellerPayout, (d_165_dt__update__tmp_h30_).buyerRefund, (d_165_dt__update__tmp_h30_).tip, (d_165_dt__update__tmp_h30_).epoch, (d_165_dt__update__tmp_h30_).expiryGate)
                return r
            if (_dafny.SeqWithoutIsStrInference((d_134_rec_)[16:48:])) != (d_130_tipHash_):
                d_170_dt__update__tmp_h31_ = r
                d_171_dt__update_hfailIndex_h24_ = d_133_i_
                d_172_dt__update_hfailNull_h24_ = False
                d_173_dt__update_hexitCode_h31_ = 1
                d_174_dt__update_hverdict_h31_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_CHAIN_BREAK")))
                r = Res_Res(d_174_dt__update_hverdict_h31_, d_173_dt__update_hexitCode_h31_, (d_170_dt__update__tmp_h31_).records, (d_170_dt__update__tmp_h31_).tornBytes, d_172_dt__update_hfailNull_h24_, d_171_dt__update_hfailIndex_h24_, (d_170_dt__update__tmp_h31_).gross, (d_170_dt__update__tmp_h31_).sellerPayout, (d_170_dt__update__tmp_h31_).buyerRefund, (d_170_dt__update__tmp_h31_).tip, (d_170_dt__update__tmp_h31_).epoch, (d_170_dt__update__tmp_h31_).expiryGate)
                return r
            d_175_sok_: bool
            out7_: bool
            out7_ = default__.SealOk(d_134_rec_)
            d_175_sok_ = out7_
            if not(d_175_sok_):
                d_176_dt__update__tmp_h32_ = r
                d_177_dt__update_hfailIndex_h25_ = d_133_i_
                d_178_dt__update_hfailNull_h25_ = False
                d_179_dt__update_hexitCode_h32_ = 1
                d_180_dt__update_hverdict_h32_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_BAD_SEAL")))
                r = Res_Res(d_180_dt__update_hverdict_h32_, d_179_dt__update_hexitCode_h32_, (d_176_dt__update__tmp_h32_).records, (d_176_dt__update__tmp_h32_).tornBytes, d_178_dt__update_hfailNull_h25_, d_177_dt__update_hfailIndex_h25_, (d_176_dt__update__tmp_h32_).gross, (d_176_dt__update__tmp_h32_).sellerPayout, (d_176_dt__update__tmp_h32_).buyerRefund, (d_176_dt__update__tmp_h32_).tip, (d_176_dt__update__tmp_h32_).epoch, (d_176_dt__update__tmp_h32_).expiryGate)
                return r
            d_181_stepId_: _dafny.Seq
            d_181_stepId_ = _dafny.SeqWithoutIsStrInference((d_134_rec_)[48:64:])
            if (d_181_stepId_) == (default__.Zeros(16)):
                d_182_dt__update__tmp_h33_ = r
                d_183_dt__update_hfailIndex_h26_ = d_133_i_
                d_184_dt__update_hfailNull_h26_ = False
                d_185_dt__update_hexitCode_h33_ = 1
                d_186_dt__update_hverdict_h33_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_EMPTY_ID")))
                r = Res_Res(d_186_dt__update_hverdict_h33_, d_185_dt__update_hexitCode_h33_, (d_182_dt__update__tmp_h33_).records, (d_182_dt__update__tmp_h33_).tornBytes, d_184_dt__update_hfailNull_h26_, d_183_dt__update_hfailIndex_h26_, (d_182_dt__update__tmp_h33_).gross, (d_182_dt__update__tmp_h33_).sellerPayout, (d_182_dt__update__tmp_h33_).buyerRefund, (d_182_dt__update__tmp_h33_).tip, (d_182_dt__update__tmp_h33_).epoch, (d_182_dt__update__tmp_h33_).expiryGate)
                return r
            d_187_sellerAmount_: int
            d_187_sellerAmount_ = default__.LE(d_134_rec_, 64, 8)
            d_188_grossSpent_: int
            d_188_grossSpent_ = default__.LE(d_134_rec_, 72, 8)
            d_189_recordTs_: int
            d_189_recordTs_ = default__.LE(d_134_rec_, 80, 8)
            if ((d_187_sellerAmount_) > (default__.MONEY__MAX)) or ((d_188_grossSpent_) > (default__.MONEY__MAX)):
                d_190_dt__update__tmp_h34_ = r
                d_191_dt__update_hfailIndex_h27_ = d_133_i_
                d_192_dt__update_hfailNull_h27_ = False
                d_193_dt__update_hexitCode_h34_ = 1
                d_194_dt__update_hverdict_h34_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_AMOUNT_NOT_MONEY")))
                r = Res_Res(d_194_dt__update_hverdict_h34_, d_193_dt__update_hexitCode_h34_, (d_190_dt__update__tmp_h34_).records, (d_190_dt__update__tmp_h34_).tornBytes, d_192_dt__update_hfailNull_h27_, d_191_dt__update_hfailIndex_h27_, (d_190_dt__update__tmp_h34_).gross, (d_190_dt__update__tmp_h34_).sellerPayout, (d_190_dt__update__tmp_h34_).buyerRefund, (d_190_dt__update__tmp_h34_).tip, (d_190_dt__update__tmp_h34_).epoch, (d_190_dt__update__tmp_h34_).expiryGate)
                return r
            if (d_189_recordTs_) < (d_129_tsPrev_):
                d_195_dt__update__tmp_h35_ = r
                d_196_dt__update_hfailIndex_h28_ = d_133_i_
                d_197_dt__update_hfailNull_h28_ = False
                d_198_dt__update_hexitCode_h35_ = 1
                d_199_dt__update_hverdict_h35_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_SEQ_MISMATCH")))
                r = Res_Res(d_199_dt__update_hverdict_h35_, d_198_dt__update_hexitCode_h35_, (d_195_dt__update__tmp_h35_).records, (d_195_dt__update__tmp_h35_).tornBytes, d_197_dt__update_hfailNull_h28_, d_196_dt__update_hfailIndex_h28_, (d_195_dt__update__tmp_h35_).gross, (d_195_dt__update__tmp_h35_).sellerPayout, (d_195_dt__update__tmp_h35_).buyerRefund, (d_195_dt__update__tmp_h35_).tip, (d_195_dt__update__tmp_h35_).epoch, (d_195_dt__update__tmp_h35_).expiryGate)
                return r
            if (d_188_grossSpent_) != ((d_127_gross_) + (d_187_sellerAmount_)):
                d_200_dt__update__tmp_h36_ = r
                d_201_dt__update_hfailIndex_h29_ = d_133_i_
                d_202_dt__update_hfailNull_h29_ = False
                d_203_dt__update_hexitCode_h36_ = 1
                d_204_dt__update_hverdict_h36_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_CHAIN_BREAK")))
                r = Res_Res(d_204_dt__update_hverdict_h36_, d_203_dt__update_hexitCode_h36_, (d_200_dt__update__tmp_h36_).records, (d_200_dt__update__tmp_h36_).tornBytes, d_202_dt__update_hfailNull_h29_, d_201_dt__update_hfailIndex_h29_, (d_200_dt__update__tmp_h36_).gross, (d_200_dt__update__tmp_h36_).sellerPayout, (d_200_dt__update__tmp_h36_).buyerRefund, (d_200_dt__update__tmp_h36_).tip, (d_200_dt__update__tmp_h36_).epoch, (d_200_dt__update__tmp_h36_).expiryGate)
                return r
            if (d_188_grossSpent_) > (d_65_cap_):
                d_205_dt__update__tmp_h37_ = r
                d_206_dt__update_hfailIndex_h30_ = d_133_i_
                d_207_dt__update_hfailNull_h30_ = False
                d_208_dt__update_hexitCode_h37_ = 1
                d_209_dt__update_hverdict_h37_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_OVER_CAP")))
                r = Res_Res(d_209_dt__update_hverdict_h37_, d_208_dt__update_hexitCode_h37_, (d_205_dt__update__tmp_h37_).records, (d_205_dt__update__tmp_h37_).tornBytes, d_207_dt__update_hfailNull_h30_, d_206_dt__update_hfailIndex_h30_, (d_205_dt__update__tmp_h37_).gross, (d_205_dt__update__tmp_h37_).sellerPayout, (d_205_dt__update__tmp_h37_).buyerRefund, (d_205_dt__update__tmp_h37_).tip, (d_205_dt__update__tmp_h37_).epoch, (d_205_dt__update__tmp_h37_).expiryGate)
                return r
            if (d_181_stepId_) in (d_128_settled_):
                d_210_dt__update__tmp_h38_ = r
                d_211_dt__update_hfailIndex_h31_ = d_133_i_
                d_212_dt__update_hfailNull_h31_ = False
                d_213_dt__update_hexitCode_h38_ = 1
                d_214_dt__update_hverdict_h38_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_DUPLICATE_ID")))
                r = Res_Res(d_214_dt__update_hverdict_h38_, d_213_dt__update_hexitCode_h38_, (d_210_dt__update__tmp_h38_).records, (d_210_dt__update__tmp_h38_).tornBytes, d_212_dt__update_hfailNull_h31_, d_211_dt__update_hfailIndex_h31_, (d_210_dt__update__tmp_h38_).gross, (d_210_dt__update__tmp_h38_).sellerPayout, (d_210_dt__update__tmp_h38_).buyerRefund, (d_210_dt__update__tmp_h38_).tip, (d_210_dt__update__tmp_h38_).epoch, (d_210_dt__update__tmp_h38_).expiryGate)
                return r
            d_132_expiryEvaluated_ = True
            if (obsPresent) and ((observedNow) >= (d_66_expiresAt_)):
                d_215_dt__update__tmp_h39_ = r
                d_216_dt__update_hexpiryGate_h0_ = True
                d_217_dt__update_hfailIndex_h32_ = d_133_i_
                d_218_dt__update_hfailNull_h32_ = False
                d_219_dt__update_hexitCode_h39_ = 1
                d_220_dt__update_hverdict_h39_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_EXPIRED")))
                r = Res_Res(d_220_dt__update_hverdict_h39_, d_219_dt__update_hexitCode_h39_, (d_215_dt__update__tmp_h39_).records, (d_215_dt__update__tmp_h39_).tornBytes, d_218_dt__update_hfailNull_h32_, d_217_dt__update_hfailIndex_h32_, (d_215_dt__update__tmp_h39_).gross, (d_215_dt__update__tmp_h39_).sellerPayout, (d_215_dt__update__tmp_h39_).buyerRefund, (d_215_dt__update__tmp_h39_).tip, (d_215_dt__update__tmp_h39_).epoch, d_216_dt__update_hexpiryGate_h0_)
                return r
            if tapePresent:
                d_221_seal32_: _dafny.Seq
                d_221_seal32_ = _dafny.SeqWithoutIsStrInference((d_134_rec_)[96:128:])
                if (len(tape)) < (((d_133_i_) * (128)) + (128)):
                    d_222_dt__update__tmp_h40_ = r
                    d_223_dt__update_hfailIndex_h33_ = d_133_i_
                    d_224_dt__update_hfailNull_h33_ = False
                    d_225_dt__update_hexitCode_h40_ = 1
                    d_226_dt__update_hverdict_h40_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_BAD_SIGNATURE")))
                    r = Res_Res(d_226_dt__update_hverdict_h40_, d_225_dt__update_hexitCode_h40_, (d_222_dt__update__tmp_h40_).records, (d_222_dt__update__tmp_h40_).tornBytes, d_224_dt__update_hfailNull_h33_, d_223_dt__update_hfailIndex_h33_, (d_222_dt__update__tmp_h40_).gross, (d_222_dt__update__tmp_h40_).sellerPayout, (d_222_dt__update__tmp_h40_).buyerRefund, (d_222_dt__update__tmp_h40_).tip, (d_222_dt__update__tmp_h40_).epoch, (d_222_dt__update__tmp_h40_).expiryGate)
                    return r
                d_227_sA_: _dafny.Seq
                d_227_sA_ = _dafny.SeqWithoutIsStrInference((tape)[(d_133_i_) * (128):((d_133_i_) * (128)) + (64):])
                d_228_sB_: _dafny.Seq
                d_228_sB_ = _dafny.SeqWithoutIsStrInference((tape)[((d_133_i_) * (128)) + (64):((d_133_i_) * (128)) + (128):])
                d_229_rA_: int
                out8_: int
                out8_ = Ed.default__.VerifyStrict(d_98_keyA_, d_227_sA_, d_221_seal32_)
                d_229_rA_ = out8_
                d_230_rB_: int
                out9_: int
                out9_ = Ed.default__.VerifyStrict(d_99_keyB_, d_228_sB_, d_221_seal32_)
                d_230_rB_ = out9_
                if ((d_229_rA_) != (0)) or ((d_230_rB_) != (0)):
                    d_231_dt__update__tmp_h41_ = r
                    d_232_dt__update_hfailIndex_h34_ = d_133_i_
                    d_233_dt__update_hfailNull_h34_ = False
                    d_234_dt__update_hexitCode_h41_ = 1
                    d_235_dt__update_hverdict_h41_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_BAD_SIGNATURE")))
                    r = Res_Res(d_235_dt__update_hverdict_h41_, d_234_dt__update_hexitCode_h41_, (d_231_dt__update__tmp_h41_).records, (d_231_dt__update__tmp_h41_).tornBytes, d_233_dt__update_hfailNull_h34_, d_232_dt__update_hfailIndex_h34_, (d_231_dt__update__tmp_h41_).gross, (d_231_dt__update__tmp_h41_).sellerPayout, (d_231_dt__update__tmp_h41_).buyerRefund, (d_231_dt__update__tmp_h41_).tip, (d_231_dt__update__tmp_h41_).epoch, (d_231_dt__update__tmp_h41_).expiryGate)
                    return r
            d_127_gross_ = d_188_grossSpent_
            d_128_settled_ = (d_128_settled_) | (_dafny.Set({d_181_stepId_}))
            d_129_tsPrev_ = d_189_recordTs_
            d_236_nh_: _dafny.Seq
            out10_: _dafny.Seq
            out10_ = default__.WholeHash(d_134_rec_)
            d_236_nh_ = out10_
            d_130_tipHash_ = d_236_nh_
            d_133_i_ = (d_133_i_) + (1)
        d_237_lastTipHex_: _dafny.Seq
        d_237_lastTipHex_ = default__.HexOf(d_130_tipHash_)
        if tipPresent:
            d_238_want_: _dafny.Seq
            d_238_want_ = default__.LowerHexSeq(expectTip)
            if (d_238_want_) != (d_237_lastTipHex_):
                d_239_dt__update__tmp_h42_ = r
                d_240_dt__update_hexpiryGate_h1_ = False
                d_241_dt__update_hepoch_h0_ = 0
                d_242_dt__update_htip_h0_ = _dafny.SeqWithoutIsStrInference([])
                d_243_dt__update_hbuyerRefund_h0_ = 0
                d_244_dt__update_hsellerPayout_h0_ = 0
                d_245_dt__update_hgross_h0_ = 0
                d_246_dt__update_hfailIndex_h35_ = 0
                d_247_dt__update_hfailNull_h35_ = True
                d_248_dt__update_hexitCode_h42_ = 1
                d_249_dt__update_hverdict_h42_ = default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "REJECT_CHAIN_BREAK")))
                r = Res_Res(d_249_dt__update_hverdict_h42_, d_248_dt__update_hexitCode_h42_, (d_239_dt__update__tmp_h42_).records, (d_239_dt__update__tmp_h42_).tornBytes, d_247_dt__update_hfailNull_h35_, d_246_dt__update_hfailIndex_h35_, d_245_dt__update_hgross_h0_, d_244_dt__update_hsellerPayout_h0_, d_243_dt__update_hbuyerRefund_h0_, d_242_dt__update_htip_h0_, d_241_dt__update_hepoch_h0_, d_240_dt__update_hexpiryGate_h1_)
                return r
        d_250_hasSteps_: bool
        d_250_hasSteps_ = (d_0_records_) >= (2)
        d_251_finalGross_: int
        d_251_finalGross_ = d_127_gross_
        d_252_payout_: int
        d_252_payout_ = d_251_finalGross_
        d_253_refund_: int
        d_253_refund_ = (d_65_cap_) - (d_251_finalGross_)
        d_254_eg_: bool
        d_254_eg_ = d_250_hasSteps_
        if (d_1_tornBytes_) > (0):
            r = Res_Res(default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "ACCEPT_TORN_TAIL"))), 4, d_0_records_, d_1_tornBytes_, True, 0, d_251_finalGross_, d_252_payout_, d_253_refund_, d_237_lastTipHex_, d_0_records_, d_254_eg_)
        elif True:
            r = Res_Res(default__.Asc(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "ACCEPT"))), 0, d_0_records_, d_1_tornBytes_, True, 0, d_251_finalGross_, d_252_payout_, d_253_refund_, d_237_lastTipHex_, d_0_records_, d_254_eg_)
        return r

    @_dafny.classproperty
    def MAGIC(instance):
        return _dafny.SeqWithoutIsStrInference([70, 86, 50])
    @_dafny.classproperty
    def MONEY__MAX(instance):
        return 9223372036854775807

class Res:
    @classmethod
    def default(cls, ):
        return lambda: Res_Res(_dafny.Seq({}), int(0), int(0), int(0), False, int(0), int(0), int(0), int(0), _dafny.Seq({}), int(0), False)
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Res(self) -> bool:
        return isinstance(self, Res_Res)

class Res_Res(Res, NamedTuple('Res', [('verdict', Any), ('exitCode', Any), ('records', Any), ('tornBytes', Any), ('failNull', Any), ('failIndex', Any), ('gross', Any), ('sellerPayout', Any), ('buyerRefund', Any), ('tip', Any), ('epoch', Any), ('expiryGate', Any)])):
    def __dafnystr__(self) -> str:
        return f'Verifier.Res.Res({_dafny.string_of(self.verdict)}, {_dafny.string_of(self.exitCode)}, {_dafny.string_of(self.records)}, {_dafny.string_of(self.tornBytes)}, {_dafny.string_of(self.failNull)}, {_dafny.string_of(self.failIndex)}, {_dafny.string_of(self.gross)}, {_dafny.string_of(self.sellerPayout)}, {_dafny.string_of(self.buyerRefund)}, {_dafny.string_of(self.tip)}, {_dafny.string_of(self.epoch)}, {_dafny.string_of(self.expiryGate)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Res_Res) and self.verdict == __o.verdict and self.exitCode == __o.exitCode and self.records == __o.records and self.tornBytes == __o.tornBytes and self.failNull == __o.failNull and self.failIndex == __o.failIndex and self.gross == __o.gross and self.sellerPayout == __o.sellerPayout and self.buyerRefund == __o.buyerRefund and self.tip == __o.tip and self.epoch == __o.epoch and self.expiryGate == __o.expiryGate
    def __hash__(self) -> int:
        return super().__hash__()

