/* -*- mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */

/*
 *  Main authors:
 *     Guido Tack <guido.tack@monash.edu>
 */

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <minizinc/flat_exp.hh>

#include <list>

namespace MiniZinc {

ASTString op_to_builtin(EnvI& env, Expression* op_lhs, Expression* op_rhs, BinOpType bot) {
  std::string builtin;

  if (op_rhs->type().st() == Type::ST_SET) {
    switch (bot) {
      case BOT_LE:
        return env.constants.ids.set_.lt;
      case BOT_LQ:
        return env.constants.ids.set_.le;
      case BOT_GR:
        return env.constants.ids.set_.gt;
      case BOT_GQ:
        return env.constants.ids.set_.ge;
      case BOT_EQ:
        return env.constants.ids.set_.eq;
      case BOT_NQ:
        return env.constants.ids.set_.ne;
      case BOT_IN:
        return env.constants.ids.set_.in;
      case BOT_SUBSET:
        return env.constants.ids.set_.subset;
      case BOT_SUPERSET:
        return env.constants.ids.set_.superset;
      case BOT_UNION:
        return env.constants.ids.set_.union_;
      case BOT_DIFF:
        return env.constants.ids.set_.diff;
      case BOT_SYMDIFF:
        return env.constants.ids.set_.symdiff;
      case BOT_INTERSECT:
        return env.constants.ids.set_.intersect;
      default:
        throw InternalError("Operator not yet implemented");
    }
  }
  Type tt(op_rhs->type().bt() != Type::BT_BOT ? op_rhs->type() : op_lhs->type());
  if (tt.bt() == Type::BT_INT) {
    switch (bot) {
      case BOT_PLUS:
        return env.constants.ids.int_.plus;
      case BOT_MINUS:
        return env.constants.ids.int_.minus;
      case BOT_MULT:
        return env.constants.ids.int_.times;
      case BOT_POW:
        return env.constants.ids.pow;
      case BOT_IDIV:
        return env.constants.ids.int_.div;
      case BOT_MOD:
        return env.constants.ids.int_.mod;
      case BOT_LE:
        return env.constants.ids.int_.lt;
      case BOT_LQ:
        return env.constants.ids.int_.le;
      case BOT_GR:
        return env.constants.ids.int_.gt;
      case BOT_GQ:
        return env.constants.ids.int_.ge;
      case BOT_EQ:
        return env.constants.ids.int_.eq;
      case BOT_NQ:
        return env.constants.ids.int_.ne;
      default:
        throw InternalError("Operator not yet implemented");
    }
  }
  if (tt.bt() == Type::BT_FLOAT) {
    switch (bot) {
      case BOT_PLUS:
        return env.constants.ids.float_.plus;
      case BOT_MINUS:
        return env.constants.ids.float_.minus;
      case BOT_MULT:
        return env.constants.ids.float_.times;
      case BOT_POW:
        return env.constants.ids.pow;
      case BOT_DIV:
        return env.constants.ids.float_.div;
      case BOT_MOD:
        return env.constants.ids.float_.mod;
      case BOT_LE:
        return env.constants.ids.float_.lt;
      case BOT_LQ:
        return env.constants.ids.float_.le;
      case BOT_GR:
        return env.constants.ids.float_.gt;
      case BOT_GQ:
        return env.constants.ids.float_.ge;
      case BOT_EQ:
        return env.constants.ids.float_.eq;
      case BOT_NQ:
        return env.constants.ids.float_.ne;
      default:
        throw InternalError("Operator not yet implemented");
    }
  }
  if (tt.bt() == Type::BT_BOOL) {
    switch (bot) {
      case BOT_LE:
        return env.constants.ids.bool_.lt;
      case BOT_IMPL:
      // fall through
      case BOT_LQ:
        return env.constants.ids.bool_.le;
      case BOT_GR:
        return env.constants.ids.bool_.gt;
      case BOT_RIMPL:
      // fall through
      case BOT_GQ:
        return env.constants.ids.bool_.ge;
      case BOT_EQUIV:
      case BOT_EQ:
        return env.constants.ids.bool_.eq;
      case BOT_XOR:
      // fall through
      case BOT_NQ:
        return env.constants.ids.bool_.ne;
      case BOT_OR:
        return env.constants.ids.bool_.or_;
      case BOT_AND:
        return env.constants.ids.bool_.and_;
      default:
        throw InternalError("Operator not yet implemented");
    }
  }
  throw InternalError("Operator not yet implemented");
}

ASTString op_to_id(BinOpType bot) {
  switch (bot) {
    case BOT_PLUS:
      return ASTString("'+'");
    case BOT_MINUS:
      return ASTString("'-'");
    case BOT_MULT:
      return ASTString("'*'");
    case BOT_DIV:
      return ASTString("'/'");
    case BOT_IDIV:
      return ASTString("'div'");
    case BOT_MOD:
      return ASTString("'mod'");
    case BOT_LE:
      return ASTString("'<'");
    case BOT_LQ:
      return ASTString("'<='");
    case BOT_GR:
      return ASTString("'>'");
    case BOT_GQ:
      return ASTString("'>='");
    case BOT_EQ:
      return ASTString("'='");
    case BOT_NQ:
      return ASTString("'!='");
    case BOT_IN:
      return ASTString("'in'");
    case BOT_SUBSET:
      return ASTString("'subset'");
    case BOT_SUPERSET:
      return ASTString("'superset'");
    case BOT_UNION:
      return ASTString("'union'");
    case BOT_DIFF:
      return ASTString("'diff'");
    case BOT_SYMDIFF:
      return ASTString("'symdiff'");
    case BOT_INTERSECT:
      return ASTString("'intersect'");
    case BOT_PLUSPLUS:
      return ASTString("'++'");
    case BOT_DOTDOT:
      return ASTString("'..'");
    case BOT_EQUIV:
      return ASTString("'<->'");
    case BOT_IMPL:
      return ASTString("'->'");
    case BOT_RIMPL:
      return ASTString("'<-'");
    case BOT_OR:
      return ASTString("'\\/'");
    case BOT_AND:
      return ASTString("'/\\'");
    case BOT_XOR:
      return ASTString("'xor'");
    default:
      assert(false);
      return ASTString("");
  }
}

bool is_reverse_map(EnvI& env, BinOp* e) {
  return e->ann().contains(env.constants.ann.is_reverse_map);
}

template <class Lit>
void collect_linexps(EnvI& env, typename LinearTraits<Lit>::Val in_c, Expression* exp,
                     std::vector<typename LinearTraits<Lit>::Val>& coeffs,
                     std::vector<KeepAlive>& vars, typename LinearTraits<Lit>::Val& constval) {
  typedef typename LinearTraits<Lit>::Val Val;
  struct StackItem {
    Expression* e;
    Val c;
    StackItem(Expression* e0, Val c0) : e(e0), c(c0) {}
  };
  std::vector<StackItem> stack;
  stack.push_back(StackItem(exp, in_c));
  while (!stack.empty()) {
    Expression* e = stack.back().e;
    Val c = stack.back().c;
    stack.pop_back();
    if (e == nullptr) {
      continue;
    }
    if (e->type().isPar()) {
      constval += c * LinearTraits<Lit>::eval(env, e);
    } else if (Lit* l = e->dynamicCast<Lit>()) {
      constval += c * l->v();
    } else if (auto* bo = e->dynamicCast<BinOp>()) {
      switch (bo->op()) {
        case BOT_PLUS:
          stack.push_back(StackItem(bo->lhs(), c));
          stack.push_back(StackItem(bo->rhs(), c));
          break;
        case BOT_MINUS:
          stack.push_back(StackItem(bo->lhs(), c));
          stack.push_back(StackItem(bo->rhs(), -c));
          break;
        case BOT_MULT:
          if (bo->lhs()->type().isPar()) {
            stack.push_back(StackItem(bo->rhs(), c * LinearTraits<Lit>::eval(env, bo->lhs())));
          } else if (bo->rhs()->type().isPar()) {
            stack.push_back(StackItem(bo->lhs(), c * LinearTraits<Lit>::eval(env, bo->rhs())));
          } else {
            coeffs.push_back(c);
            vars.emplace_back(e);
          }
          break;
        case BOT_DIV:
          if (bo->rhs()->isa<FloatLit>() && bo->rhs()->cast<FloatLit>()->v() == 1.0) {
            stack.push_back(StackItem(bo->lhs(), c));
          } else {
            coeffs.push_back(c);
            vars.emplace_back(e);
          }
          break;
        case BOT_IDIV:
          if (bo->rhs()->isa<IntLit>() && bo->rhs()->cast<IntLit>()->v() == 1) {
            stack.push_back(StackItem(bo->lhs(), c));
          } else {
            coeffs.push_back(c);
            vars.emplace_back(e);
          }
          break;
        default:
          coeffs.push_back(c);
          vars.emplace_back(e);
          break;
      }
      //      } else if (Call* call = e->dynamicCast<Call>()) {
      //        /// TODO! Handle sum, lin_exp (maybe not that important?)
    } else {
      coeffs.push_back(c);
      vars.emplace_back(e);
    }
  }
}

template <class Lit>
KeepAlive mklinexp(EnvI& env, typename LinearTraits<Lit>::Val c0,
                   typename LinearTraits<Lit>::Val c1, Expression* e0, Expression* e1) {
  typedef typename LinearTraits<Lit>::Val Val;
  GCLock lock;

  std::vector<Val> coeffs;
  std::vector<KeepAlive> vars;
  Val constval = 0;
  collect_linexps<Lit>(env, c0, e0, coeffs, vars, constval);
  collect_linexps<Lit>(env, c1, e1, coeffs, vars, constval);
  simplify_lin<Lit>(coeffs, vars, constval);
  KeepAlive ka;
  if (coeffs.empty()) {
    ka = LinearTraits<Lit>::newLit(constval);
  } else if (coeffs.size() == 1 && coeffs[0] == 1 && constval == 0) {
    ka = vars[0];
  } else {
    std::vector<Expression*> coeffs_e(coeffs.size());
    for (auto i = static_cast<unsigned int>(coeffs.size()); i--;) {
      if (!LinearTraits<Lit>::finite(coeffs[i])) {
        throw FlatteningError(
            env, e0->loc(),
            "unbounded coefficient in linear expression."
            " Make sure variables involved in non-linear/logical expressions have finite bounds"
            " in their definition or via constraints");
      }
      coeffs_e[i] = LinearTraits<Lit>::newLit(coeffs[i]);
    }
    std::vector<Expression*> vars_e(vars.size());
    for (auto i = static_cast<unsigned int>(vars.size()); i--;) {
      vars_e[i] = vars[i]();
    }

    std::vector<Expression*> args(3);
    args[0] = new ArrayLit(e0->loc(), coeffs_e);
    Type t = coeffs_e[0]->type();
    t.dim(1);
    args[0]->type(t);
    args[1] = new ArrayLit(e0->loc(), vars_e);
    Type tt = vars_e[0]->type();
    tt.dim(1);
    args[1]->type(tt);
    args[2] = LinearTraits<Lit>::newLit(constval);
    Call* c = new Call(e0->loc().introduce(), env.constants.ids.lin_exp, args);
    add_path_annotation(env, c);
    tt = args[1]->type();
    tt.dim(0);
    c->decl(env.model->matchFn(env, c, false));
    if (c->decl() == nullptr) {
      throw FlatteningError(env, c->loc(), "cannot find matching declaration");
    }
    c->type(c->decl()->rtype(env, args, false));
    ka = c;
  }
  assert(ka());
  return ka;
}

Call* aggregate_and_or_ops(EnvI& env, BinOp* bo, bool negateArgs, BinOpType bot) {
  assert(bot == BOT_AND || bot == BOT_OR);
  BinOpType negbot = (bot == BOT_AND ? BOT_OR : BOT_AND);
  typedef std::pair<Expression*, bool> arg_literal;
  typedef std::list<arg_literal> arg_literal_l;
  arg_literal_l bo_args({arg_literal(bo->lhs(), !negateArgs), arg_literal(bo->rhs(), !negateArgs)});
  std::vector<Expression*> output_pos;
  std::vector<Expression*> output_neg;
  auto i = bo_args.begin();
  while (i != bo_args.end()) {
    auto* bo_arg = i->first->dynamicCast<BinOp>();
    UnOp* uo_arg = i->first->dynamicCast<UnOp>();
    bool positive = i->second;
    if ((bo_arg != nullptr) && positive && bo_arg->op() == bot) {
      i->first = bo_arg->lhs();
      i++;
      bo_args.insert(i, arg_literal(bo_arg->rhs(), true));
      i--;
      i--;
    } else if ((bo_arg != nullptr) && !positive && bo_arg->op() == negbot) {
      i->first = bo_arg->lhs();
      i++;
      bo_args.insert(i, arg_literal(bo_arg->rhs(), false));
      i--;
      i--;
    } else if ((uo_arg != nullptr) && !positive && uo_arg->op() == UOT_NOT) {
      i->first = uo_arg->e();
      i->second = true;
    } else if (bot == BOT_OR && (uo_arg != nullptr) && positive && uo_arg->op() == UOT_NOT) {
      output_neg.push_back(uo_arg->e());
      i++;
    } else {
      if (positive) {
        output_pos.push_back(i->first);
      } else {
        output_neg.push_back(i->first);
      }
      i++;
    }
  }
  Call* c;
  std::vector<Expression*> c_args(1);
  if (bot == BOT_AND) {
    for (auto& i : output_neg) {
      UnOp* neg_arg = new UnOp(i->loc(), UOT_NOT, i);
      neg_arg->type(i->type());
      output_pos.push_back(neg_arg);
    }
    auto* al = new ArrayLit(bo->loc().introduce(), output_pos);
    Type al_t = bo->type();
    al_t.dim(1);
    al->type(al_t);
    env.annotateFromCallStack(al);
    c_args[0] = al;
    c = new Call(bo->loc().introduce(),
                 bot == BOT_AND ? env.constants.ids.forall : env.constants.ids.exists, c_args);
  } else {
    auto* al_pos = new ArrayLit(bo->loc().introduce(), output_pos);
    Type al_t = bo->type();
    al_t.dim(1);
    al_pos->type(al_t);
    env.annotateFromCallStack(al_pos);
    c_args[0] = al_pos;
    if (!output_neg.empty()) {
      auto* al_neg = new ArrayLit(bo->loc().introduce(), output_neg);
      al_neg->type(al_t);
      env.annotateFromCallStack(al_neg);
      c_args.push_back(al_neg);
    }
    c = new Call(bo->loc().introduce(),
                 output_neg.empty() ? env.constants.ids.exists : env.constants.ids.clause, c_args);
  }
  c->decl(env.model->matchFn(env, c, false));
  assert(c->decl());
  Type t = c->decl()->rtype(env, c_args, false);
  t.cv(bo->type().cv());
  c->type(t);
  return c;
}

/// Return a lin_exp or id if \a e is a lin_exp or id
template <class Lit>
Expression* get_linexp(EnvI& env, Expression* e) {
  for (;;) {
    if (e && e->eid() == Expression::E_ID && e != env.constants.absent) {
      if (e->cast<Id>()->decl()->e()) {
        e = e->cast<Id>()->decl()->e();
      } else {
        break;
      }
    } else {
      break;
    }
  }
  if (e && (e->isa<Id>() || e->isa<Lit>() ||
            (e->isa<Call>() && e->cast<Call>()->id() == env.constants.ids.lin_exp))) {
    return e;
  }
  return nullptr;
}

template <class Lit>
void flatten_linexp_binop(EnvI& env, const Ctx& ctx, VarDecl* r, VarDecl* b, EE& ret,
                          Expression* le0, Expression* le1, BinOpType& bot, bool doubleNeg,
                          std::vector<EE>& ees, std::vector<KeepAlive>& args, ASTString& callid) {
  typedef typename LinearTraits<Lit>::Val Val;
  std::vector<Val> coeffv;
  std::vector<KeepAlive> alv;
  Val d = 0;
  Expression* le[2] = {le0, le1};

  // Assign linear expression directly if one side is an Id.
  Id* assignTo = nullptr;
  if (bot == BOT_EQ && ctx.b == C_ROOT) {
    if (le0->isa<Id>()) {
      assignTo = le0->cast<Id>();
    } else if (le1->isa<Id>()) {
      assignTo = le1->cast<Id>();
    }
  } else {
    if (le0->type().isPar()) {
      Val v0 = LinearTraits<Lit>::eval(env, le0);
      if (!v0.isFinite()) {
        bool result;
        switch (bot) {
          case BOT_NQ:
            result = true;
            break;
          case BOT_LE:
          case BOT_LQ:
            result = v0.isMinusInfinity();
            break;
          case BOT_GR:
          case BOT_GQ:
            result = v0.isPlusInfinity();
            break;
          default:
            assert(false);
        }
        if (doubleNeg) {
          result = !result;
        }
        ees[2].b = env.constants.boollit(result);
        ret.r = conj(env, r, ctx, ees);
        return;
      }
    } else if (le1->type().isPar()) {
      Val v1 = LinearTraits<Lit>::eval(env, le1);
      if (!v1.isFinite()) {
        bool result;
        switch (bot) {
          case BOT_NQ:
            result = true;
            break;
          case BOT_LE:
          case BOT_LQ:
            result = v1.isPlusInfinity();
            break;
          case BOT_GR:
          case BOT_GQ:
            result = v1.isMinusInfinity();
            break;
          default:
            assert(false);
        }
        if (doubleNeg) {
          result = !result;
        }
        ees[2].b = env.constants.boollit(result);
        ret.r = conj(env, r, ctx, ees);
        return;
      }
    }
  }

  for (unsigned int i = 0; i < 2; i++) {
    Val sign = (i == 0 ? 1 : -1);
    if (Lit* l = le[i]->dynamicCast<Lit>()) {
      try {
        d += sign * l->v();
      } catch (ArithmeticError& e) {
        throw EvalError(env, l->loc(), e.msg());
      }
    } else if (le[i]->isa<Id>()) {
      coeffv.push_back(sign);
      alv.emplace_back(le[i]);
    } else if (Call* sc = le[i]->dynamicCast<Call>()) {
      GCLock lock;
      ArrayLit* sc_coeff = eval_array_lit(env, sc->arg(0));
      ArrayLit* sc_al = eval_array_lit(env, sc->arg(1));
      try {
        d += sign * LinearTraits<Lit>::eval(env, sc->arg(2));
        for (unsigned int j = 0; j < sc_coeff->size(); j++) {
          coeffv.push_back(sign * LinearTraits<Lit>::eval(env, (*sc_coeff)[j]));
          alv.emplace_back((*sc_al)[j]);
        }
      } catch (ArithmeticError& e) {
        throw EvalError(env, sc->loc(), e.msg());
      }

    } else {
      throw EvalError(env, le[i]->loc(),
                      "Internal error, unexpected expression inside linear expression");
    }
  }
  simplify_lin<Lit>(coeffv, alv, d);
  if (coeffv.empty()) {
    bool result;
    switch (bot) {
      case BOT_LE:
        result = (0 < -d);
        break;
      case BOT_LQ:
        result = (0 <= -d);
        break;
      case BOT_GR:
        result = (0 > -d);
        break;
      case BOT_GQ:
        result = (0 >= -d);
        break;
      case BOT_EQ:
        result = (0 == -d);
        break;
      case BOT_NQ:
        result = (0 != -d);
        break;
      default:
        assert(false);
        break;
    }
    if (doubleNeg) {
      result = !result;
    }
    ees[2].b = env.constants.boollit(result);
    ret.r = conj(env, r, ctx, ees);
    return;
  }
  if (coeffv.size() == 1 && std::abs(coeffv[0]) == 1) {
    if (coeffv[0] == -1) {
      switch (bot) {
        case BOT_LE:
          bot = BOT_GR;
          break;
        case BOT_LQ:
          bot = BOT_GQ;
          break;
        case BOT_GR:
          bot = BOT_LE;
          break;
        case BOT_GQ:
          bot = BOT_LQ;
          break;
        default:
          break;
      }
    } else {
      d = -d;
    }
    typename LinearTraits<Lit>::Bounds ib = LinearTraits<Lit>::computeBounds(env, alv[0]());
    if (ib.valid) {
      bool failed = false;
      bool subsumed = false;
      switch (bot) {
        case BOT_LE:
          subsumed = ib.u < d;
          failed = ib.l >= d;
          break;
        case BOT_LQ:
          subsumed = ib.u <= d;
          failed = ib.l > d;
          break;
        case BOT_GR:
          subsumed = ib.l > d;
          failed = ib.u <= d;
          break;
        case BOT_GQ:
          subsumed = ib.l >= d;
          failed = ib.u < d;
          break;
        case BOT_EQ:
          subsumed = ib.l == d && ib.u == d;
          failed = ib.u < d || ib.l > d;
          break;
        case BOT_NQ:
          subsumed = ib.u < d || ib.l > d;
          failed = ib.l == d && ib.u == d;
          break;
        default:
          break;
      }
      if (doubleNeg) {
        std::swap(subsumed, failed);
      }
      if (subsumed) {
        ees[2].b = env.constants.literalTrue;
        ret.r = conj(env, r, ctx, ees);
        return;
      }
      if (failed) {
        ees[2].b = env.constants.literalFalse;
        ret.r = conj(env, r, ctx, ees);
        return;
      }
    }

    if (ctx.b == C_ROOT && alv[0]()->isa<Id>() && bot == BOT_EQ) {
      GCLock lock;
      VarDecl* vd = alv[0]()->cast<Id>()->decl();
      if (vd->ti()->domain()) {
        typename LinearTraits<Lit>::Domain domain =
            LinearTraits<Lit>::evalDomain(env, vd->ti()->domain());
        if (LinearTraits<Lit>::domainContains(domain, d)) {
          if (!LinearTraits<Lit>::domainEquals(domain, d)) {
            set_computed_domain(env, vd, LinearTraits<Lit>::newDomain(d), false);
          }
          ret.r = bind(env, ctx, r, env.constants.literalTrue);
        } else {
          ret.r = bind(env, ctx, r, env.constants.literalFalse);
        }
      } else {
        set_computed_domain(env, vd, LinearTraits<Lit>::newDomain(d), false);
        ret.r = bind(env, ctx, r, env.constants.literalTrue);
      }
    } else {
      GCLock lock;
      Expression* e0;
      Expression* e1;
      BinOpType old_bot = bot;
      Val old_d = d;
      switch (bot) {
        case BOT_LE:
          e0 = alv[0]();
          if (e0->type().isint()) {
            d--;
            bot = BOT_LQ;
          }
          e1 = LinearTraits<Lit>::newLit(d);
          break;
        case BOT_GR:
          e1 = alv[0]();
          if (e1->type().isint()) {
            d++;
            bot = BOT_LQ;
          } else {
            bot = BOT_LE;
          }
          e0 = LinearTraits<Lit>::newLit(d);
          break;
        case BOT_GQ:
          e0 = LinearTraits<Lit>::newLit(d);
          e1 = alv[0]();
          bot = BOT_LQ;
          break;
        default:
          e0 = alv[0]();
          e1 = LinearTraits<Lit>::newLit(d);
      }
      if (ctx.b == C_ROOT && alv[0]()->isa<Id>() && !env.hasReverseMapper(alv[0]()->cast<Id>()) &&
          alv[0]()->cast<Id>()->decl()->ti()->domain()) {
        VarDecl* vd = alv[0]()->cast<Id>()->decl();
        typename LinearTraits<Lit>::Domain domain =
            LinearTraits<Lit>::evalDomain(env, vd->ti()->domain());
        typename LinearTraits<Lit>::Domain ndomain =
            LinearTraits<Lit>::limitDomain(old_bot, domain, old_d);
        if (domain && ndomain) {
          if (LinearTraits<Lit>::domainEmpty(ndomain)) {
            ret.r = bind(env, ctx, r, env.constants.literalFalse);
            return;
          }
          if (!LinearTraits<Lit>::domainEquals(domain, ndomain)) {
            ret.r = bind(env, ctx, r, env.constants.literalTrue);
            set_computed_domain(env, vd, LinearTraits<Lit>::newDomain(ndomain), false);

            if (r == env.constants.varTrue) {
              auto* bo = new BinOp(Location().introduce(), e0, bot, e1);
              bo->type(Type::varbool());
              std::vector<Expression*> boargs(2);
              boargs[0] = e0;
              boargs[1] = e1;
              Call* c = new Call(Location(), op_to_builtin(env, e0, e1, bot), boargs);
              c->type(Type::varbool());
              c->decl(env.model->matchFn(env, c, false));
              auto it = env.cseMapFind(c);
              if (it != env.cseMapEnd()) {
                if (Id* ident = it->second.r()->template dynamicCast<Id>()) {
                  bind(env, Ctx(), ident->decl(), env.constants.literalTrue);
                  it->second.r = env.constants.literalTrue;
                }
                if (Id* ident = it->second.b()->template dynamicCast<Id>()) {
                  bind(env, Ctx(), ident->decl(), env.constants.literalTrue);
                  it->second.b = env.constants.literalTrue;
                }
              }
            }
          }
          return;
        }
      }
      args.emplace_back(e0);
      args.emplace_back(e1);
    }
  } else if (bot == BOT_EQ && coeffv.size() == 2 && coeffv[0] == -coeffv[1] && d == 0) {
    Id* id0 = alv[0]()->cast<Id>();
    Id* id1 = alv[1]()->cast<Id>();
    if (ctx.b == C_ROOT && r == env.constants.varTrue &&
        (id0->decl()->e() == nullptr || id1->decl()->e() == nullptr)) {
      if (id0->decl()->e()) {
        (void)bind(env, ctx, id1->decl(), id0);
      } else {
        (void)bind(env, ctx, id0->decl(), id1);
      }
    } else {
      callid = LinearTraits<Lit>::id_eq();
      args.emplace_back(alv[0]());
      args.emplace_back(alv[1]());
    }
  } else {
    GCLock lock;
    if (assignTo != nullptr) {
      Val resultCoeff = 0;
      typename LinearTraits<Lit>::Bounds bounds(d, d, true);
      for (auto i = static_cast<unsigned int>(coeffv.size()); i--;) {
        if (alv[i]() == assignTo) {
          resultCoeff = coeffv[i];
          continue;
        }
        typename LinearTraits<Lit>::Bounds bound = LinearTraits<Lit>::computeBounds(env, alv[i]());

        if (bound.valid && LinearTraits<Lit>::finite(bound)) {
          if (coeffv[i] > 0) {
            bounds.l += coeffv[i] * bound.l;
            bounds.u += coeffv[i] * bound.u;
          } else {
            bounds.l += coeffv[i] * bound.u;
            bounds.u += coeffv[i] * bound.l;
          }
        } else {
          bounds.valid = false;
          break;
        }
      }
      if (bounds.valid && resultCoeff != 0) {
        if (resultCoeff < 0) {
          bounds.l = LinearTraits<Lit>::floorDiv(bounds.l, -resultCoeff);
          bounds.u = LinearTraits<Lit>::ceilDiv(bounds.u, -resultCoeff);
        } else {
          Val bl = bounds.l;
          bounds.l = LinearTraits<Lit>::ceilDiv(bounds.u, -resultCoeff);
          bounds.u = LinearTraits<Lit>::floorDiv(bl, -resultCoeff);
        }
        VarDecl* vd = assignTo->decl();
        if (vd->ti()->domain()) {
          typename LinearTraits<Lit>::Domain domain =
              LinearTraits<Lit>::evalDomain(env, vd->ti()->domain());
          if (LinearTraits<Lit>::domainIntersects(domain, bounds.l, bounds.u)) {
            typename LinearTraits<Lit>::Domain new_domain =
                LinearTraits<Lit>::intersectDomain(domain, bounds.l, bounds.u);
            if (!LinearTraits<Lit>::domainEquals(domain, new_domain)) {
              set_computed_domain(env, vd, LinearTraits<Lit>::newDomain(new_domain), false);
            }
          } else {
            ret.r = bind(env, ctx, r, env.constants.literalFalse);
          }
        } else {
          set_computed_domain(env, vd, LinearTraits<Lit>::newDomain(bounds.l, bounds.u), true);
        }
      }
    }

    int coeff_sign;
    LinearTraits<Lit>::constructLinBuiltin(env, bot, callid, coeff_sign, d);
    std::vector<Expression*> coeff_ev(coeffv.size());
    for (auto i = static_cast<unsigned int>(coeff_ev.size()); i--;) {
      coeff_ev[i] = LinearTraits<Lit>::newLit(coeff_sign * coeffv[i]);
    }
    auto* ncoeff = new ArrayLit(Location().introduce(), coeff_ev);
    Type t = coeff_ev[0]->type();
    t.dim(1);
    ncoeff->type(t);
    args.emplace_back(ncoeff);
    std::vector<Expression*> alv_e(alv.size());
    Type tt = alv[0]()->type();
    tt.dim(1);
    for (auto i = static_cast<unsigned int>(alv.size()); i--;) {
      if (alv[i]()->type().isvar()) {
        tt.ti(Type::TI_VAR);
      }
      alv_e[i] = alv[i]();
    }
    auto* nal = new ArrayLit(Location().introduce(), alv_e);
    nal->type(tt);
    args.emplace_back(nal);
    Lit* il = LinearTraits<Lit>::newLit(-d);
    args.push_back(il);
  }
}

EE flatten_binop(EnvI& env, const Ctx& input_ctx, Expression* e, VarDecl* r, VarDecl* b);

EE flatten_nonbool_op(EnvI& env, const Ctx& ctx, const Ctx& ctx0, const Ctx& ctx1, Expression* e,
                      VarDecl* r, VarDecl* b, bool isBuiltin, BinOp* bo, BinOpType bot) {
  assert(!ctx0.neg);
  assert(!ctx1.neg);

  EE ret;

  EE e0 = flat_exp(env, ctx0, bo->lhs(), nullptr, b);
  EE e1 = flat_exp(env, ctx1, bo->rhs(), nullptr, b);

  if (e0.r()->type().isPar() && e1.r()->type().isPar()) {
    GCLock lock;
    auto* parbo = new BinOp(bo->loc(), e0.r(), bo->op(), e1.r());
    std::vector<Expression*> args(2);
    args[0] = e0.r();
    args[1] = e1.r();
    FunctionI* fi = env.model->matchFn(env, bo->opToString(), args, false);
    parbo->decl(fi);
    Type tt = fi->rtype(env, {e0.r()->type(), e1.r()->type()}, false);
    assert(tt.isPar());
    parbo->type(tt);
    try {
      Expression* res = eval_par(env, parbo);
      assert(!res->type().isunknown());
      ret.r = bind(env, ctx, r, res);
      std::vector<EE> ees(2);
      ees[0].b = e0.b;
      ees[1].b = e1.b;
      ret.b = conj(env, b, Ctx(), ees);
    } catch (ResultUndefinedError&) {
      ret.r = create_dummy_value(env, e->type());
      ret.b = bind(env, Ctx(), b, env.constants.literalFalse);
    }
    return ret;
  }

  if (!isBuiltin && (e0.r()->type() != bo->lhs()->type() || e1.r()->type() != bo->rhs()->type())) {
    // The type has changed after flattening the arguments. E.g., the type may have gone
    // from opt to non-opt. In this case, flatten the whole BinOp again with the new
    // arguments, to ensure that the correct built-in is selected if necessary.
    KeepAlive ka;
    {
      GCLock lock;
      auto* newBo = new BinOp(bo->loc(), e0.r(), bo->op(), e1.r());
      std::vector<Expression*> args({e0.r(), e1.r()});
      FunctionI* fi = env.model->matchFn(env, bo->opToString(), args, true);
      assert(fi != nullptr);
      Type ty = fi->rtype(env, args, true);
      newBo->type(ty);
      newBo->decl(fi);
      ka = newBo;
    }
    return flatten_binop(env, ctx, ka(), r, b);
  }

  if (isBuiltin && bot == BOT_MULT) {
    Expression* e0r = e0.r();
    Expression* e1r = e1.r();
    if (e0r->type().isPar()) {
      std::swap(e0r, e1r);
    }
    if (e1r->type().isPar() && e1r->type().isint()) {
      IntVal coeff = eval_int(env, e1r);
      KeepAlive ka = mklinexp<IntLit>(env, coeff, 0, e0r, nullptr);
      return flat_exp(env, ctx, ka(), r, b);
    }
    if (e1r->type().isPar() && e1r->type().isfloat()) {
      FloatVal coeff = eval_float(env, e1r);
      KeepAlive ka = mklinexp<FloatLit>(env, coeff, 0.0, e0r, nullptr);
      return flat_exp(env, ctx, ka(), r, b);
    }
  } else if (isBuiltin && (bot == BOT_DIV || bot == BOT_IDIV)) {
    Expression* e0r = e0.r();
    Expression* e1r = e1.r();
    if (e1r->type().isPar() && e1r->type().isint()) {
      IntVal coeff = eval_int(env, e1r);
      if (coeff == 1) {
        return flat_exp(env, ctx, e0r, r, b);
      }
    } else if (e1r->type().isPar() && e1r->type().isfloat()) {
      FloatVal coeff = eval_float(env, e1r);
      if (coeff == 1.0) {
        return flat_exp(env, ctx, e0r, r, b);
      }
      KeepAlive ka = mklinexp<FloatLit>(env, 1.0 / coeff, 0.0, e0r, nullptr);
      return flat_exp(env, ctx, ka(), r, b);
    }
  }

  GC::lock();
  std::vector<Expression*> args(2);
  args[0] = e0.r();
  args[1] = e1.r();
  Call* cc;
  if (!isBuiltin) {
    cc = new Call(bo->loc().introduce(), bo->opToString(), args);
  } else {
    cc = new Call(bo->loc().introduce(), op_to_builtin(env, args[0], args[1], bot), args);
  }
  cc->type(bo->type());
  EnvI::CSEMap::iterator cit;
  if ((cit = env.cseMapFind(cc)) != env.cseMapEnd()) {
    ret.b = bind(env, Ctx(), b, env.ignorePartial ? env.constants.literalTrue : cit->second.b());
    ret.r = bind(env, ctx, r, cit->second.r());
  } else {
    if (FunctionI* fi = env.model->matchFn(env, cc->id(), args, false)) {
      assert(cc->type() == fi->rtype(env, args, false));
      cc->decl(fi);
      cc->type(cc->decl()->rtype(env, args, false));
      KeepAlive ka(cc);
      GC::unlock();
      EE ee = flat_exp(env, ctx, cc, r, ctx.partialityVar(env));
      GC::lock();
      ret.r = ee.r;
      std::vector<EE> ees(3);
      ees[0].b = e0.b;
      ees[1].b = e1.b;
      ees[2].b = ee.b;
      ret.b = conj(env, b, Ctx(), ees);
    } else {
      add_path_annotation(env, cc);
      ret.r = bind(env, ctx, r, cc);
      std::vector<EE> ees(2);
      ees[0].b = e0.b;
      ees[1].b = e1.b;
      ret.b = conj(env, b, Ctx(), ees);
      if (!ctx.neg) {
        env.cseMapInsert(cc, ret);
      }
    }
  }
  GC::unlock();
  return ret;
}

template <class Lit>
bool flatten_dom_constraint(EnvI& env, Ctx& ctx, VarDecl* vd, Expression* dom, VarDecl* r,
                            EE& ret) {
  Id* ident = vd->id();
  if (ctx.b == C_ROOT && r == env.constants.varTrue) {
    if (vd->ti()->domain() == nullptr) {
      vd->ti()->domain(dom);
    } else {
      GCLock lock;
      auto* newdom = LinearTraits<Lit>::evalDomain(env, dom);
      while (ident != nullptr) {
        bool changeDom = false;
        if (ident->decl()->ti()->domain() != nullptr) {
          auto* domain = LinearTraits<Lit>::evalDomain(env, ident->decl()->ti()->domain());
          auto* interdom = LinearTraits<Lit>::intersectDomain(domain, newdom);
          if (!LinearTraits<Lit>::domainEquals(domain, interdom)) {
            newdom = interdom;
            changeDom = true;
          }
        } else {
          changeDom = true;
        }
        if (ident->type().st() == Type::ST_PLAIN && newdom->empty()) {
          env.fail();
        } else if (changeDom) {
          set_computed_domain(env, ident->decl(), new SetLit(Location().introduce(), newdom),
                              false);
          if (ident->decl()->e() == nullptr && newdom->min() == newdom->max() &&
              !vd->type().isSet()) {
            ident->decl()->e(LinearTraits<Lit>::newLit(newdom->min()));
          }
        }
        ident = ident->decl()->e() != nullptr ? ident->decl()->e()->dynamicCast<Id>() : nullptr;
      }
    }
    ret.r = bind(env, ctx, r, env.constants.literalTrue);
    return true;
  }
  if (vd->ti()->domain() != nullptr) {
    // check if current domain is already subsumed or falsified by this constraint
    GCLock lock;
    auto* check_dom = LinearTraits<Lit>::evalDomain(env, dom);
    auto* domain = LinearTraits<Lit>::evalDomain(env, ident->decl()->ti()->domain());

    if (LinearTraits<Lit>::domainSubset(domain, check_dom)) {
      // the constraint is subsumed
      ret.r = bind(env, ctx, r, env.constants.literalTrue);
      return true;
    }
    if (vd->type().st() == Type::ST_PLAIN && LinearTraits<Lit>::domainDisjoint(check_dom, domain)) {
      // only for var int/var float (for var set of int, subset can never fail because of the
      // domain)
      // the constraint is false
      ret.r = bind(env, ctx, r, env.constants.literalFalse);
      return true;
    }
  }
  return false;
}

EE flatten_bool_op(EnvI& env, Ctx& ctx, const Ctx& ctx0, const Ctx& ctx1, Expression* e, VarDecl* r,
                   VarDecl* b, bool isBuiltin, BinOp* bo, BinOpType bot, bool doubleNeg) {
  EE ret;

  auto* boe0 = bo->lhs();
  auto* boe1 = bo->rhs();

  bool inRootCtx = (ctx0.b == ctx1.b && ctx0.b == C_ROOT && b == env.constants.varTrue);
  EE e0 = flat_exp(env, ctx0, boe0, nullptr, inRootCtx ? b : nullptr);
  EE e1 = flat_exp(env, ctx1, boe1, nullptr, inRootCtx ? b : nullptr);

  ret.b = bind(env, Ctx(), b, env.constants.literalTrue);

  std::vector<EE> ees(3);
  ees[0].b = e0.b;
  ees[1].b = e1.b;

  if (isfalse(env, e0.b()) || isfalse(env, e1.b())) {
    ees.resize(2);
    ret.r = conj(env, r, ctx, ees);
    return ret;
  }

  if (e0.r()->type().isPar() && e1.r()->type().isPar()) {
    GCLock lock;
    auto* bo_par = new BinOp(e->loc(), e0.r(), bot, e1.r());
    std::vector<Expression*> args({e0.r(), e1.r()});
    bo_par->decl(env.model->matchFn(env, bo_par->opToString(), args, false));
    if (bo_par->decl() == nullptr) {
      throw FlatteningError(env, bo_par->loc(), "cannot find matching declaration");
    }
    bo_par->type(Type::parbool());
    bool bo_val = eval_bool(env, bo_par);
    if (doubleNeg) {
      bo_val = !bo_val;
    }
    ees[2].b = env.constants.boollit(bo_val);
    ret.r = conj(env, r, ctx, ees);
    return ret;
  }

  if (e1.r()->type().isPar() && e0.r()->isa<Id>() && (bot == BOT_IN || bot == BOT_SUBSET)) {
    if (e0.r()->type().bt() == Type::BT_INT &&
        flatten_dom_constraint<IntLit>(env, ctx, e0.r()->cast<Id>()->decl(), e1.r(), r, ret)) {
      return ret;
    }
    if (e0.r()->type().bt() == Type::BT_FLOAT &&
        flatten_dom_constraint<FloatLit>(env, ctx, e0.r()->cast<Id>()->decl(), e1.r(), r, ret)) {
      return ret;
    }
  }

  std::vector<KeepAlive> args;
  ASTString callid;

  Expression* le0 = nullptr;
  Expression* le1 = nullptr;

  if (e0.r()->type().isint() && !e0.r()->type().isOpt() && bot != BOT_IN) {
    le0 = get_linexp<IntLit>(env, e0.r());
  } else if (e0.r()->type().isfloat() && !e0.r()->type().isOpt() && bot != BOT_IN) {
    le0 = get_linexp<FloatLit>(env, e0.r());
  }
  if (le0 != nullptr) {
    if (e0.r()->type().isint() && e1.r()->type().isint() && !e1.r()->type().isOpt()) {
      le1 = get_linexp<IntLit>(env, e1.r());
    } else if (e0.r()->type().isfloat() && e1.r()->type().isfloat() && !e1.r()->type().isOpt()) {
      le1 = get_linexp<FloatLit>(env, e1.r());
    }
  }
  if (le1 != nullptr) {
    if (e0.r()->type().isint()) {
      flatten_linexp_binop<IntLit>(env, ctx, r, b, ret, le0, le1, bot, doubleNeg, ees, args,
                                   callid);
    } else {
      flatten_linexp_binop<FloatLit>(env, ctx, r, b, ret, le0, le1, bot, doubleNeg, ees, args,
                                     callid);
    }
  } else {
    switch (bot) {
      case BOT_GR:
        std::swap(e0, e1);
        bot = BOT_LE;
        break;
      case BOT_GQ:
        std::swap(e0, e1);
        bot = BOT_LQ;
        break;
      default:
        break;
    }
    args.push_back(e0.r);
    args.push_back(e1.r);
  }

  if (!args.empty()) {
    GC::lock();

    bool idIsOp = false;
    if (callid.empty()) {
      assert(args.size() == 2);
      if (!isBuiltin) {
        callid = op_to_id(bot);
        idIsOp = true;
      } else {
        callid = op_to_builtin(env, args[0](), args[1](), bot);
      }
    }

    std::vector<Expression*> args_e(args.size());
    for (auto i = static_cast<unsigned int>(args.size()); (i--) != 0U;) {
      args_e[i] = args[i]();
    }
    Call* cc = new Call(e->loc().introduce(), callid, args_e);
    cc->decl(env.model->matchFn(env, cc->id(), args_e, false));
    if (cc->decl() == nullptr) {
      throw FlatteningError(env, cc->loc(), "cannot find matching declaration");
    }
    if (idIsOp && cc->decl()->e() == nullptr) {
      // This is in fact a built-in operator, but we only found out after
      // constructing the call
      cc = new Call(e->loc().introduce(), op_to_builtin(env, args[0](), args[1](), bot), args_e);
      cc->decl(env.model->matchFn(env, cc->id(), args_e, false));
      if (cc->decl() == nullptr) {
        throw FlatteningError(env, cc->loc(), "cannot find matching declaration");
      }
    }
    cc->type(cc->decl()->rtype(env, args_e, false));

    // add defines_var annotation if applicable
    Id* assignTo = nullptr;
    if (bot == BOT_EQ && ctx.b == C_ROOT) {
      if ((le0 != nullptr) && le0->isa<Id>()) {
        assignTo = le0->cast<Id>();
      } else if ((le1 != nullptr) && le1->isa<Id>()) {
        assignTo = le1->cast<Id>();
      }
      if (assignTo != nullptr) {
        make_defined_var(env, assignTo->decl()->flat(), cc);
      }
    }

    auto cit = env.cseMapFind(cc);
    if (cit != env.cseMapEnd()) {
      ees[2].b = cit->second.r();
      if (doubleNeg) {
        Type t = ees[2].b()->type();
        ees[2].b = new UnOp(Location().introduce(), UOT_NOT, ees[2].b());
        ees[2].b()->type(t);
      }
      if (Id* id = ees[2].b()->dynamicCast<Id>()) {
        add_ctx_ann(env, id->decl(), ctx.b);
      }
      ret.r = conj(env, r, ctx, ees);
      GC::unlock();
    } else {
      bool singleExp = true;
      for (auto& ee : ees) {
        if (!istrue(env, ee.b())) {
          singleExp = false;
          break;
        }
      }
      KeepAlive ka(cc);
      GC::unlock();
      if (singleExp) {
        if (doubleNeg) {
          ctx.b = -ctx.b;
          ctx.neg = !ctx.neg;
        }
        ret.r = flat_exp(env, ctx, cc, r, ctx.partialityVar(env)).r;
      } else {
        ees[2].b = flat_exp(env, Ctx(), cc, nullptr, env.constants.varTrue).r;
        if (doubleNeg) {
          GCLock lock;
          Type t = ees[2].b()->type();
          ees[2].b = new UnOp(Location().introduce(), UOT_NOT, ees[2].b());
          ees[2].b()->type(t);
        }
        if (Id* id = ees[2].b()->dynamicCast<Id>()) {
          add_ctx_ann(env, id->decl(), ctx.b);
        }
        ret.r = conj(env, r, ctx, ees);
      }
    }
  } else {
    ret.r = conj(env, r, ctx, ees);
  }
  return ret;
}

EE flatten_binop(EnvI& env, const Ctx& input_ctx, Expression* e, VarDecl* r, VarDecl* b) {
  Ctx ctx = input_ctx;
  CallStackItem _csi(env, e);
  EE ret;
  auto* bo = e->cast<BinOp>();
  if (is_reverse_map(env, bo)) {
    CallArgItem cai(env);
    Id* id = bo->lhs()->dynamicCast<Id>();
    if (id == nullptr) {
      throw EvalError(env, bo->lhs()->loc(), "Reverse mappers are only defined for identifiers");
    }
    if (bo->op() != BOT_EQ && bo->op() != BOT_EQUIV) {
      throw EvalError(env, bo->loc(), "Reverse mappers have to use `=` as the operator");
    }
    Call* c = bo->rhs()->dynamicCast<Call>();
    if (c == nullptr) {
      throw EvalError(env, bo->rhs()->loc(), "Reverse mappers require call on right hand side");
    }

    std::vector<Expression*> args(c->argCount());
    for (unsigned int i = 0; i < c->argCount(); i++) {
      Id* idi = c->arg(i)->dynamicCast<Id>();
      if (idi == nullptr) {
        throw EvalError(env, c->arg(i)->loc(),
                        "Reverse mapper calls require identifiers as arguments");
      }
      EE ee = flat_exp(env, Ctx(), idi, nullptr, env.constants.varTrue);
      args[i] = ee.r();
    }

    EE ee = flat_exp(env, Ctx(), id, nullptr, env.constants.varTrue);

    GCLock lock;
    Call* revMap = new Call(Location().introduce(), c->id(), args);

    args.push_back(ee.r());
    Call* keepAlive = new Call(Location().introduce(), env.constants.varRedef->id(), args);
    keepAlive->type(Type::varbool());
    keepAlive->decl(env.constants.varRedef);
    ret = flat_exp(env, Ctx(), keepAlive, env.constants.varTrue, env.constants.varTrue);

    if (ee.r()->isa<Id>()) {
      env.reverseMappers.insert(ee.r()->cast<Id>(), revMap);
    }
    return ret;
  }
  if ((bo->op() == BOT_EQ || bo->op() == BOT_EQUIV) &&
      (bo->lhs() == env.constants.absent || bo->rhs() == env.constants.absent)) {
    GCLock lock;
    std::vector<Expression*> args(1);
    args[0] = bo->lhs() == env.constants.absent ? bo->rhs() : bo->lhs();
    if (args[0] != env.constants.absent) {
      Call* cr = new Call(bo->loc().introduce(), "absent", args);
      cr->decl(env.model->matchFn(env, cr, false));
      cr->type(cr->decl()->rtype(env, args, false));
      ret = flat_exp(env, ctx, cr, r, b);
    } else {
      ret.b = bind(env, Ctx(), b, env.constants.literalTrue);
      ret.r = bind(env, ctx, r, env.constants.literalTrue);
    }
    return ret;
  }
  Ctx ctx0 = ctx;
  ctx0.neg = false;
  Ctx ctx1 = ctx;
  ctx1.neg = false;
  BinOpType bot = bo->op();
  if (bo->lhs()->type().isbool()) {
    switch (bot) {
      case BOT_EQ:
        bot = BOT_EQUIV;
        break;
      case BOT_NQ:
        bot = BOT_XOR;
        break;
      case BOT_LQ:
        bot = BOT_IMPL;
        break;
      case BOT_GQ:
        bot = BOT_RIMPL;
        break;
      default:
        break;
    }
  }
  bool negArgs = false;
  bool doubleNeg = false;
  if (ctx.neg) {
    switch (bot) {
      case BOT_AND:
        ctx.b = -ctx.b;
        ctx.neg = false;
        negArgs = true;
        bot = BOT_OR;
        break;
      case BOT_OR:
        ctx.b = -ctx.b;
        ctx.neg = false;
        negArgs = true;
        bot = BOT_AND;
        break;
      default:
        break;
    }
  }
  Expression* boe0 = bo->lhs();
  Expression* boe1 = bo->rhs();
  bool isBuiltin = bo->decl() == nullptr || bo->decl()->e() == nullptr;
  switch (bot) {
    case BOT_AND:
      if (isBuiltin) {
        if (r == env.constants.varTrue) {
          Ctx nctx;
          nctx.neg = negArgs;
          nctx.b = negArgs ? C_NEG : C_ROOT;
          std::vector<Expression*> todo;
          todo.push_back(boe1);
          todo.push_back(boe0);
          while (!todo.empty()) {
            Expression* e_todo = todo.back();
            todo.pop_back();
            auto* e_bo = e_todo->dynamicCast<BinOp>();
            if ((e_bo != nullptr) && e_bo->op() == (negArgs ? BOT_OR : BOT_AND)) {
              todo.push_back(e_bo->rhs());
              todo.push_back(e_bo->lhs());
            } else {
              (void)flat_exp(env, nctx, e_todo, env.constants.varTrue, env.constants.varTrue);
            }
          }
          ret.r = bind(env, ctx, r, env.constants.literalTrue);
          break;
        }
        GC::lock();
        Call* c = aggregate_and_or_ops(env, bo, negArgs, bot);
        KeepAlive ka(c);
        GC::unlock();
        ret = flat_exp(env, ctx, c, r, b);
        if (Id* id = ret.r()->dynamicCast<Id>()) {
          add_ctx_ann(env, id->decl(), ctx.b);
        }
        break;
      }
    case BOT_OR:
      if (isBuiltin) {
        GC::lock();
        Call* c = aggregate_and_or_ops(env, bo, negArgs, bot);
        KeepAlive ka(c);
        GC::unlock();
        ret = flat_exp(env, ctx, c, r, b);
        if (Id* id = ret.r()->dynamicCast<Id>()) {
          add_ctx_ann(env, id->decl(), ctx.b);
        }
        break;
      }
    case BOT_PLUS:
      if (isBuiltin) {
        KeepAlive ka;
        if (boe0->type().isint()) {
          ka = mklinexp<IntLit>(env, 1, 1, boe0, boe1);
        } else {
          ka = mklinexp<FloatLit>(env, 1.0, 1.0, boe0, boe1);
        }
        ret = flat_exp(env, ctx, ka(), r, b);
        break;
      }
    case BOT_MINUS:
      if (isBuiltin) {
        KeepAlive ka;
        if (boe0->type().isint()) {
          ka = mklinexp<IntLit>(env, 1, -1, boe0, boe1);
        } else {
          ka = mklinexp<FloatLit>(env, 1.0, -1.0, boe0, boe1);
        }
        ret = flat_exp(env, ctx, ka(), r, b);
        break;
      }
    case BOT_MULT:
      ctx0.i = C_MIX;
      ctx1.i = C_MIX;
      if (isBuiltin && boe0->type().isint()) {
        GCLock lock;
        IntBounds bounds0 = compute_int_bounds(env, boe0);
        if (bounds0.valid && bounds0.u < 0) {
          ctx1.i = -ctx.i;
        } else if (bounds0.valid && bounds0.u >= 1) {
          ctx1.i = +ctx.i;
        }
        IntBounds bounds1 = compute_int_bounds(env, boe1);
        if (bounds1.valid && bounds1.u < 0) {
          ctx0.i = -ctx.i;
        } else if (bounds1.valid && bounds1.u >= 1) {
          ctx0.i = +ctx.i;
        }
      }
      return flatten_nonbool_op(env, ctx, ctx0, ctx1, e, r, b, isBuiltin, bo, bot);
    case BOT_IDIV:
      ctx0.i = C_MIX;
      ctx1.i = C_MIX;
      if (isBuiltin && boe0->type().isint()) {
        GCLock lock;
        IntBounds bounds0 = compute_int_bounds(env, boe0);
        if (bounds0.valid && bounds0.u < 0) {
          ctx1.i = +ctx.i;
        } else if (bounds0.valid && bounds0.u > 1) {
          ctx1.i = -ctx.i;
        }
        IntBounds bounds1 = compute_int_bounds(env, boe1);
        if (bounds1.valid && bounds1.u < 0) {
          ctx0.i = -ctx.i;
        } else if (bounds1.valid && bounds1.u > 1) {
          ctx0.i = +ctx.i;
        }
      }
      return flatten_nonbool_op(env, ctx, ctx0, ctx1, e, r, b, isBuiltin, bo, bot);
    case BOT_MOD:
    case BOT_POW:
    case BOT_DIV:
    case BOT_UNION:
    case BOT_DIFF:
    case BOT_SYMDIFF:
    case BOT_INTERSECT:
    case BOT_DOTDOT:
      ctx0.i = C_MIX;
      ctx1.i = C_MIX;
      return flatten_nonbool_op(env, ctx, ctx0, ctx1, e, r, b, isBuiltin, bo, bot);
    case BOT_RIMPL: {
      std::swap(boe0, boe1);
    }
      // fall through
    case BOT_IMPL: {
      if (ctx.b == C_ROOT && r == env.constants.varTrue && boe0->type().isPar()) {
        bool bval;
        {
          GCLock lock;
          bval = eval_bool(env, boe0);
        }
        if (bval) {
          Ctx nctx = ctx;
          nctx.neg = negArgs;
          nctx.b = negArgs ? C_NEG : C_ROOT;
          ret = flat_exp(env, nctx, boe1, env.constants.varTrue, env.constants.varTrue);
        } else {
          Ctx nctx = ctx;
          nctx.neg = negArgs;
          nctx.b = negArgs ? C_NEG : C_ROOT;
          ret = flat_exp(env, nctx, env.constants.literalTrue, env.constants.varTrue,
                         env.constants.varTrue);
        }
        break;
      }
      if (ctx.b == C_ROOT && r == env.constants.varTrue && boe1->type().isPar()) {
        bool bval;
        {
          GCLock lock;
          if (boe1->type().cv()) {
            Ctx ctx;
            ctx.b = C_MIX;
            bval = eval_bool(env, flat_cv_exp(env, ctx, boe1)());
          } else {
            bval = eval_bool(env, boe1);
          }
        }
        if (bval) {
          Ctx nctx = ctx;
          nctx.neg = negArgs;
          nctx.b = negArgs ? C_NEG : C_ROOT;
          ret = flat_exp(env, nctx, env.constants.literalTrue, env.constants.varTrue,
                         env.constants.varTrue);
          break;
        }
        Ctx nctx = ctx;
        nctx.neg = !negArgs;
        nctx.b = !negArgs ? C_NEG : C_ROOT;
        ret = flat_exp(env, nctx, boe0, env.constants.varTrue, env.constants.varTrue);
        break;
      }
      GC::lock();
      std::vector<Expression*> args;
      ASTString id;
      if (ctx.neg) {
        std::vector<Expression*> bo_args(2);
        bo_args[0] = boe0;
        bo_args[1] = new UnOp(bo->loc(), UOT_NOT, boe1);
        bo_args[1]->type(boe1->type());
        id = env.constants.ids.forall;
        args.push_back(new ArrayLit(bo->loc(), bo_args));
        args[0]->type(Type::varbool(1));
        ctx.neg = false;
        ctx.b = -ctx.b;
      } else {
        std::vector<Expression*> clause_pos(1);
        clause_pos[0] = boe1;
        std::vector<Expression*> clause_neg(1);
        clause_neg[0] = boe0;
        args.push_back(new ArrayLit(boe1->loc().introduce(), clause_pos));
        Type t0 = boe1->type();
        t0.dim(1);
        args[0]->type(t0);
        args.push_back(new ArrayLit(boe0->loc().introduce(), clause_neg));
        Type t1 = boe0->type();
        t1.dim(1);
        args[1]->type(t1);
        id = env.constants.ids.clause;
      }
      Call* c = new Call(bo->loc().introduce(), id, args);
      c->decl(env.model->matchFn(env, c, false));
      if (c->decl() == nullptr) {
        throw FlatteningError(env, c->loc(), "cannot find matching declaration");
      }
      c->type(c->decl()->rtype(env, args, false));
      KeepAlive ka(c);
      GC::unlock();
      ret = flat_exp(env, ctx, c, r, b);
      if (Id* id = ret.r()->dynamicCast<Id>()) {
        add_ctx_ann(env, id->decl(), ctx.b);
      }
    } break;
    case BOT_EQUIV:
      if (ctx.neg) {
        ctx.neg = false;
        ctx.b = -ctx.b;
        bot = BOT_XOR;
        ctx0.b = ctx1.b = C_MIX;
        return flatten_bool_op(env, ctx, ctx0, ctx1, e, r, b, isBuiltin, bo, bot, doubleNeg);
      }
      if (!boe1->type().isOpt() && istrue(env, boe0)) {
        return flat_exp(env, ctx, boe1, r, b);
      }
      if (!boe0->type().isOpt() && istrue(env, boe1)) {
        return flat_exp(env, ctx, boe0, r, b);
      }
      if (!boe0->type().isOpt() && !boe1->type().isOpt() && (r != nullptr) &&
          r == env.constants.varTrue) {
        if (boe1->type().isPar() || boe1->isa<Id>()) {
          std::swap(boe0, boe1);
        }
        if (istrue(env, boe0)) {
          return flat_exp(env, ctx1, boe1, r, b);
        }
        if (isfalse(env, boe0)) {
          ctx1.neg = true;
          ctx1.b = -ctx1.b;
          return flat_exp(env, ctx1, boe1, r, b);
        }
        ctx0.b = C_MIX;
        EE e0 = flat_exp(env, ctx0, boe0, nullptr, ctx0.partialityVar(env));
        if (istrue(env, e0.r())) {
          return flat_exp(env, ctx1, boe1, r, b);
        }
        if (isfalse(env, e0.r())) {
          ctx1.neg = true;
          ctx1.b = -ctx1.b;
          return flat_exp(env, ctx1, boe1, r, b);
        }
        Id* id = e0.r()->cast<Id>();
        ctx1.b = C_MIX;
        (void)flat_exp(env, ctx1, boe1, id->decl(), env.constants.varTrue);
        add_ctx_ann(env, id->decl(), ctx1.b);
        ret.b = bind(env, Ctx(), b, env.constants.literalTrue);
        ret.r = bind(env, Ctx(), r, env.constants.literalTrue);
        break;
      }
      ctx0.b = ctx1.b = C_MIX;
      return flatten_bool_op(env, ctx, ctx0, ctx1, e, r, b, isBuiltin, bo, bot, doubleNeg);
    case BOT_XOR:
      if (ctx.neg) {
        ctx.neg = false;
        ctx.b = -ctx.b;
        bot = BOT_EQUIV;
      }
      ctx0.b = ctx1.b = C_MIX;
      return flatten_bool_op(env, ctx, ctx0, ctx1, e, r, b, isBuiltin, bo, bot, doubleNeg);
    case BOT_LE:
      if (ctx.neg) {
        doubleNeg = true;
        bot = BOT_GQ;
        if (boe0->type().bt() == Type::BT_BOOL) {
          ctx0.b = +ctx0.b;
          ctx1.b = -ctx1.b;
        } else if (boe0->type().bt() == Type::BT_INT) {
          ctx0.i = +ctx0.b;
          ctx1.i = -ctx1.b;
        }
      } else {
        if (boe0->type().bt() == Type::BT_BOOL) {
          ctx0.b = -ctx0.b;
          ctx1.b = +ctx1.b;
        } else if (boe0->type().bt() == Type::BT_INT) {
          ctx0.i = -ctx0.b;
          ctx1.i = +ctx1.b;
        }
      }
      return flatten_bool_op(env, ctx, ctx0, ctx1, e, r, b, isBuiltin, bo, bot, doubleNeg);
    case BOT_LQ:
      if (ctx.neg) {
        doubleNeg = true;
        bot = BOT_GR;
        if (boe0->type().bt() == Type::BT_BOOL) {
          ctx0.b = +ctx0.b;
          ctx1.b = -ctx1.b;
        } else if (boe0->type().bt() == Type::BT_INT) {
          ctx0.i = +ctx0.b;
          ctx1.i = -ctx1.b;
        }
      } else {
        if (boe0->type().bt() == Type::BT_BOOL) {
          ctx0.b = -ctx0.b;
          ctx1.b = +ctx1.b;
        } else if (boe0->type().bt() == Type::BT_INT) {
          ctx0.i = -ctx0.b;
          ctx1.i = +ctx1.b;
        }
      }
      return flatten_bool_op(env, ctx, ctx0, ctx1, e, r, b, isBuiltin, bo, bot, doubleNeg);
    case BOT_GR:
      if (ctx.neg) {
        doubleNeg = true;
        bot = BOT_LQ;
        if (boe0->type().bt() == Type::BT_BOOL) {
          ctx0.b = -ctx0.b;
          ctx1.b = +ctx1.b;
        } else if (boe0->type().bt() == Type::BT_INT) {
          ctx0.i = -ctx0.b;
          ctx1.i = +ctx1.b;
        }
      } else {
        if (boe0->type().bt() == Type::BT_BOOL) {
          ctx0.b = +ctx0.b;
          ctx1.b = -ctx1.b;
        } else if (boe0->type().bt() == Type::BT_INT) {
          ctx0.i = +ctx0.b;
          ctx1.i = -ctx1.b;
        }
      }
      return flatten_bool_op(env, ctx, ctx0, ctx1, e, r, b, isBuiltin, bo, bot, doubleNeg);
    case BOT_GQ:
      if (ctx.neg) {
        doubleNeg = true;
        bot = BOT_LE;
        if (boe0->type().bt() == Type::BT_BOOL) {
          ctx0.b = -ctx0.b;
          ctx1.b = +ctx1.b;
        } else if (boe0->type().bt() == Type::BT_INT) {
          ctx0.i = -ctx0.b;
          ctx1.i = +ctx1.b;
        }
      } else {
        if (boe0->type().bt() == Type::BT_BOOL) {
          ctx0.b = +ctx0.b;
          ctx1.b = -ctx1.b;
        } else if (boe0->type().bt() == Type::BT_INT) {
          ctx0.i = +ctx0.b;
          ctx1.i = -ctx1.b;
        }
      }
      return flatten_bool_op(env, ctx, ctx0, ctx1, e, r, b, isBuiltin, bo, bot, doubleNeg);
    case BOT_EQ:
      if (ctx.neg) {
        doubleNeg = true;
        bot = BOT_NQ;
      }
      if (boe0->type().bt() == Type::BT_BOOL) {
        ctx0.b = ctx1.b = C_MIX;
      } else if (boe0->type().bt() == Type::BT_INT) {
        ctx0.i = ctx1.i = C_MIX;
      }
      return flatten_bool_op(env, ctx, ctx0, ctx1, e, r, b, isBuiltin, bo, bot, doubleNeg);
    case BOT_NQ:
      if (ctx.neg) {
        doubleNeg = true;
        bot = BOT_EQ;
      }
      if (boe0->type().bt() == Type::BT_BOOL) {
        ctx0.b = ctx1.b = C_MIX;
      } else if (boe0->type().bt() == Type::BT_INT) {
        ctx0.i = ctx1.i = C_MIX;
      }
      return flatten_bool_op(env, ctx, ctx0, ctx1, e, r, b, isBuiltin, bo, bot, doubleNeg);
    case BOT_IN:
    case BOT_SUBSET:
    case BOT_SUPERSET:
      ctx0.i = ctx1.i = C_MIX;
      return flatten_bool_op(env, ctx, ctx0, ctx1, e, r, b, isBuiltin, bo, bot, doubleNeg);
    case BOT_PLUSPLUS: {
      std::vector<EE> ee(2);
      EE eev = flat_exp(env, ctx, boe0, nullptr, ctx.partialityVar(env));
      ee[0] = eev;
      ArrayLit* al;
      if (eev.r()->isa<ArrayLit>()) {
        al = eev.r()->cast<ArrayLit>();
      } else {
        Id* id = eev.r()->cast<Id>();
        if (id->decl() == nullptr) {
          throw InternalError("undefined identifier");
        }
        if (id->decl()->e() == nullptr) {
          throw InternalError("array without initialiser not supported");
        }
        al = follow_id(id)->cast<ArrayLit>();
      }
      ArrayLit* al0 = al;
      eev = flat_exp(env, ctx, boe1, nullptr, ctx.partialityVar(env));
      ee[1] = eev;
      if (eev.r()->isa<ArrayLit>()) {
        al = eev.r()->cast<ArrayLit>();
      } else {
        Id* id = eev.r()->cast<Id>();
        if (id->decl() == nullptr) {
          throw InternalError("undefined identifier");
        }
        if (id->decl()->e() == nullptr) {
          throw InternalError("array without initialiser not supported");
        }
        al = follow_id(id)->cast<ArrayLit>();
      }
      ArrayLit* al1 = al;
      std::vector<Expression*> v(al0->size() + al1->size());
      for (unsigned int i = al0->size(); (i--) != 0U;) {
        v[i] = (*al0)[i];
      }
      for (unsigned int i = al1->size(); (i--) != 0U;) {
        v[al0->size() + i] = (*al1)[i];
      }
      GCLock lock;
      auto* alret = new ArrayLit(e->loc(), v);
      alret->type(e->type());
      ret.b = conj(env, b, Ctx(), ee);
      ret.r = bind(env, ctx, r, alret);
    } break;
  }
  return ret;
}

}  // namespace MiniZinc
