import sys
from typing import Callable, Any, TypeVar, NamedTuple
from math import floor
from itertools import count

import module_ as module_
import _dafny as _dafny
import System_ as System_
import Sha as Sha
import Ed as Ed

# Module: Model

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def Pow256(n):
        d_0___accumulator_ = 1
        while True:
            with _dafny.label():
                if (n) == (0):
                    return (1) * (d_0___accumulator_)
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) * (256)
                    in0_ = (n) - (1)
                    n = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def LED(s, off, n):
        if (n) == (0):
            return 0
        elif True:
            return ((s)[off]) + ((256) * (default__.LED(s, (off) + (1), (n) - (1))))

    @staticmethod
    def LEE(v, n):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (n) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([_dafny.euclidian_modulus(v, 256)]))
                    in0_ = _dafny.euclidian_division(v, 256)
                    in1_ = (n) - (1)
                    v = in0_
                    n = in1_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def WFHeader(h):
        return (((len((h).magic)) == (3)) and ((len((h).reserved)) == (2))) and (((h).seqno) < (default__.Pow256(8)))

    @staticmethod
    def EncHeader(h):
        return ((((h).magic) + (_dafny.SeqWithoutIsStrInference([(h).version, (h).domain, (h).kind]))) + ((h).reserved)) + (default__.LEE((h).seqno, 8))

    @staticmethod
    def DecHeader(s):
        return Header_Header(_dafny.SeqWithoutIsStrInference((s)[0:3:]), (s)[3], (s)[4], (s)[5], _dafny.SeqWithoutIsStrInference((s)[6:8:]), default__.LED(s, 8, 8))

    @staticmethod
    def Money(v):
        return ((0) <= (v)) and ((v) <= (default__.MONEY__MAX))

    @staticmethod
    def SumSeller(xs):
        d_0___accumulator_ = 0
        while True:
            with _dafny.label():
                if (len(xs)) == (0):
                    return (0) + (d_0___accumulator_)
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + ((xs)[0])
                    in0_ = _dafny.SeqWithoutIsStrInference((xs)[1::])
                    xs = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def MoneyFold(cap, steps, run):
        while True:
            with _dafny.label():
                if (len(steps)) == (0):
                    return Opt_Some(run)
                elif True:
                    d_0_sa_ = ((steps)[0])[0]
                    d_1_gf_ = ((steps)[0])[1]
                    if (not(default__.Money(d_0_sa_))) or (not(default__.Money(d_1_gf_))):
                        return Opt_None()
                    elif (d_1_gf_) != ((run) + (d_0_sa_)):
                        return Opt_None()
                    elif (d_1_gf_) > (cap):
                        return Opt_None()
                    elif True:
                        in0_ = cap
                        in1_ = _dafny.SeqWithoutIsStrInference((steps)[1::])
                        in2_ = d_1_gf_
                        cap = in0_
                        steps = in1_
                        run = in2_
                        raise _dafny.TailCall()
                break

    @staticmethod
    def Sellers(steps):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(steps)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([((steps)[0])[0]]))
                    in0_ = _dafny.SeqWithoutIsStrInference((steps)[1::])
                    steps = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def CanonSteps(run, sellers):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(sellers)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([((sellers)[0], (run) + ((sellers)[0]))]))
                    in0_ = (run) + ((sellers)[0])
                    in1_ = _dafny.SeqWithoutIsStrInference((sellers)[1::])
                    run = in0_
                    sellers = in1_
                    raise _dafny.TailCall()
                break

    @_dafny.classproperty
    def MONEY__MAX(instance):
        return 9223372036854775807

class Header:
    @classmethod
    def default(cls, ):
        return lambda: Header_Header(_dafny.Seq({}), int(0), int(0), int(0), _dafny.Seq({}), int(0))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Header(self) -> bool:
        return isinstance(self, Header_Header)

class Header_Header(Header, NamedTuple('Header', [('magic', Any), ('version', Any), ('domain', Any), ('kind', Any), ('reserved', Any), ('seqno', Any)])):
    def __dafnystr__(self) -> str:
        return f'Model.Header.Header({_dafny.string_of(self.magic)}, {_dafny.string_of(self.version)}, {_dafny.string_of(self.domain)}, {_dafny.string_of(self.kind)}, {_dafny.string_of(self.reserved)}, {_dafny.string_of(self.seqno)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Header_Header) and self.magic == __o.magic and self.version == __o.version and self.domain == __o.domain and self.kind == __o.kind and self.reserved == __o.reserved and self.seqno == __o.seqno
    def __hash__(self) -> int:
        return super().__hash__()


class Opt:
    @classmethod
    def default(cls, ):
        return lambda: Opt_None()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_None(self) -> bool:
        return isinstance(self, Opt_None)
    @property
    def is_Some(self) -> bool:
        return isinstance(self, Opt_Some)

class Opt_None(Opt, NamedTuple('None_', [])):
    def __dafnystr__(self) -> str:
        return f'Model.Opt.None'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Opt_None)
    def __hash__(self) -> int:
        return super().__hash__()

class Opt_Some(Opt, NamedTuple('Some', [('v', Any)])):
    def __dafnystr__(self) -> str:
        return f'Model.Opt.Some({_dafny.string_of(self.v)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Opt_Some) and self.v == __o.v
    def __hash__(self) -> int:
        return super().__hash__()

