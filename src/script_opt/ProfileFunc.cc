// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/ProfileFunc.h"

#include <unistd.h>
#include <cerrno>

#include "zeek/Desc.h"
#include "zeek/Func.h"
#include "zeek/Stmt.h"
#include "zeek/script_opt/FuncInfo.h"
#include "zeek/script_opt/IDOptInfo.h"

namespace zeek::detail {

// Computes the profiling hash of a Obj based on its (deterministic)
// description.
p_hash_type p_hash(const Obj* o) {
    ODesc d;
    d.SetDeterminism(true);
    o->Describe(&d);
    return p_hash(d.Description());
}

ProfileFunc::ProfileFunc(const Func* func, const StmtPtr& body, bool _abs_rec_fields) {
    profiled_func = func;
    profiled_body = body.get();
    abs_rec_fields = _abs_rec_fields;

    auto ft = func->GetType()->AsFuncType();
    auto& fcaps = ft->GetCaptures();

    if ( fcaps ) {
        int offset = 0;

        for ( auto& c : *fcaps ) {
            auto cid = c.Id().get();
            captures.insert(cid);
            captures_offsets[cid] = offset++;
        }
    }

    Profile(ft, body);
}

ProfileFunc::ProfileFunc(const Stmt* s, bool _abs_rec_fields) {
    profiled_body = s;
    abs_rec_fields = _abs_rec_fields;
    s->Traverse(this);
}

ProfileFunc::ProfileFunc(const Expr* e, bool _abs_rec_fields) {
    profiled_expr = e;

    abs_rec_fields = _abs_rec_fields;

    if ( e->Tag() == EXPR_LAMBDA ) {
        auto func = e->AsLambdaExpr();

        int offset = 0;

        for ( auto oid : func->OuterIDs() ) {
            captures.insert(oid);
            captures_offsets[oid] = offset++;
        }

        Profile(func->GetType()->AsFuncType(), func->Ingredients()->Body());
    }

    else
        // We don't have a function type, so do the traversal
        // directly.
        e->Traverse(this);
}

void ProfileFunc::Profile(const FuncType* ft, const StmtPtr& body) {
    num_params = ft->Params()->NumFields();
    TrackType(ft);
    body->Traverse(this);
}

TraversalCode ProfileFunc::PreStmt(const Stmt* s) {
    stmts.push_back(s);

    switch ( s->Tag() ) {
        case STMT_INIT:
            for ( const auto& id : s->AsInitStmt()->Inits() ) {
                inits.insert(id.get());

                auto& t = id->GetType();
                TrackType(t);

                auto attrs = id->GetAttrs();
                if ( attrs )
                    constructor_attrs[attrs.get()] = t;
            }

            // Don't traverse further into the statement, since we
            // don't want to view the identifiers as locals unless
            // they're also used elsewhere.
            return TC_ABORTSTMT;

        case STMT_WHEN: {
            ++num_when_stmts;

            auto w = s->AsWhenStmt();
            auto wi = w->Info();

            for ( auto wl : wi->WhenNewLocals() )
                when_locals.insert(wl);
        } break;

        case STMT_FOR: {
            auto sf = s->AsForStmt();
            auto loop_vars = sf->LoopVars();
            auto value_var = sf->ValueVar();

            for ( auto id : *loop_vars )
                locals.insert(id);

            if ( value_var )
                locals.insert(value_var.get());
        } break;

        case STMT_SWITCH: {
            // If this is a type-case switch statement, then find the
            // identifiers created so we can add them to our list of
            // locals.  Ideally this wouldn't be necessary since *surely*
            // if one bothers to define such an identifier then it'll be
            // subsequently used, and we'll pick up the local that way ...
            // but if for some reason it's not, then we would have an
            // incomplete list of locals that need to be tracked.

            auto sw = s->AsSwitchStmt();
            bool is_type_switch = false;

            for ( auto& c : *sw->Cases() ) {
                auto idl = c->TypeCases();
                if ( idl ) {
                    for ( auto id : *idl )
                        // Make sure it's not a placeholder
                        // identifier, used when there's
                        // no explicit one.
                        if ( id->Name() )
                            locals.insert(id);

                    is_type_switch = true;
                }
            }

            if ( is_type_switch )
                type_switches.insert(sw);
            else
                expr_switches.insert(sw);
        } break;

        case STMT_ADD:
        case STMT_DELETE: {
            auto ad_stmt = static_cast<const AddDelStmt*>(s);
            auto ad_e = ad_stmt->StmtExpr();
            auto& lhs_t = ad_e->GetOp1()->GetType();
            if ( lhs_t->Tag() == TYPE_TABLE )
                aggr_mods.insert(lhs_t.get());
        } break;

        default: break;
    }

    return TC_CONTINUE;
}

TraversalCode ProfileFunc::PreExpr(const Expr* e) {
    exprs.push_back(e);

    TrackType(e->GetType());

    switch ( e->Tag() ) {
        case EXPR_CONST: constants.push_back(e->AsConstExpr()); break;

        case EXPR_NAME: {
            auto n = e->AsNameExpr();
            auto id = n->Id();

            // Turns out that NameExpr's can be constructed using a
            // different Type* than that of the identifier itself,
            // so be sure we track the latter too.
            TrackType(id->GetType());

            if ( id->IsGlobal() ) {
                globals.insert(id);
                all_globals.insert(id);

                const auto& t = id->GetType();
                if ( t->Tag() == TYPE_FUNC && t->AsFuncType()->Flavor() == FUNC_FLAVOR_EVENT )
                    events.insert(id->Name());

                break;
            }

            // This is a tad ugly.  Unfortunately due to the
            // weird way that Zeek function *declarations* work,
            // there's no reliable way to get the list of
            // parameters for a function *definition*, since
            // they can have different names than what's present
            // in the declaration.  So we identify them directly,
            // by knowing that they come at the beginning of the
            // frame ... and being careful to avoid misconfusing
            // a lambda capture with a low frame offset as a
            // parameter.
            if ( captures.count(id) == 0 && id->Offset() < num_params )
                params.insert(id);

            locals.insert(id);

            break;
        }

        case EXPR_FIELD: {
            auto f = e->AsFieldExpr()->Field();
            if ( abs_rec_fields )
                addl_hashes.push_back(p_hash(f));
            else {
                auto fn = e->AsFieldExpr()->FieldName();
                addl_hashes.push_back(p_hash(fn));
            }
            aggr_refs.insert(std::make_pair(e->GetOp1()->GetType().get(), f));
        }

        break;

        case EXPR_HAS_FIELD:
            if ( abs_rec_fields ) {
                auto f = e->AsHasFieldExpr()->Field();
                addl_hashes.push_back(std::hash<int>{}(f));
            }
            else {
                auto fn = e->AsHasFieldExpr()->FieldName();
                addl_hashes.push_back(std::hash<std::string>{}(fn));
            }
            break;

        case EXPR_INDEX: {
            auto lhs_t = e->GetOp1()->GetType();
            if ( lhs_t->Tag() == TYPE_TABLE )
                aggr_refs.insert(std::make_pair(lhs_t.get(), 0));
        } break;

        case EXPR_INCR:
        case EXPR_DECR:
        case EXPR_ADD_TO:
        case EXPR_REMOVE_FROM:
        case EXPR_ASSIGN: {
            auto lhs = e->GetOp1();

            if ( lhs->Tag() == EXPR_REF )
                lhs = lhs->GetOp1();

            else if ( e->Tag() == EXPR_ASSIGN )
                // This isn't a direct assignment, but instead an overloaded
                // use of "=" such as in a table constructor.
                break;

            auto lhs_t = lhs->GetType();
            if ( IsAggr(lhs_t->Tag()) ) {
                // Determine which aggregate is being modified.  For an
                // assignment "a[b] = aggr", it's not a[b]'s type but rather
                // a's type. However, for any of the others, e.g. "a[b] -= aggr"
                // it is a[b]'s type.
                if ( e->Tag() == EXPR_ASSIGN ) {
                    // The following might be nil for an assignment like
                    // "aggr = new_val".
                    auto lhs_parent = lhs->GetOp1();
                    if ( lhs_parent )
                        aggr_mods.insert(lhs_parent->GetType().get());
                }
                else
                    // Operation directly modifies LHS.
                    aggr_mods.insert(lhs_t.get());
            }

            if ( lhs->Tag() == EXPR_NAME ) {
                auto id = lhs->AsNameExpr()->Id();
                TrackAssignment(id);

                if ( e->Tag() == EXPR_ASSIGN ) {
                    auto a_e = static_cast<const AssignExpr*>(e);
                    auto& av = a_e->AssignVal();
                    if ( av )
                        // This is a funky "local" assignment
                        // inside a when clause.
                        when_locals.insert(id);
                }
                break;
            }


        } break;

        case EXPR_CALL: {
            auto c = e->AsCallExpr();
            auto f = c->Func();

            if ( f->Tag() != EXPR_NAME ) {
                does_indirect_calls = true;
                return TC_CONTINUE;
            }

            auto n = f->AsNameExpr();
            auto func = n->Id();

            if ( ! func->IsGlobal() ) {
                does_indirect_calls = true;
                return TC_CONTINUE;
            }

            all_globals.insert(func);

            auto func_v = func->GetVal();
            if ( func_v ) {
                auto func_vf = func_v->AsFunc();

                if ( func_vf->GetKind() == Func::SCRIPT_FUNC ) {
                    auto sf = static_cast<ScriptFunc*>(func_vf);
                    script_calls.insert(sf);
                }
                else
                    BiF_globals.insert(func);
            }
            else {
                // We could complain, but for now we don't, because
                // if we're invoked prior to full Zeek initialization,
                // the value might indeed not there yet.
                // printf("no function value for global %s\n", func->Name());
            }

            // Recurse into the arguments.
            auto args = c->Args();
            args->Traverse(this);

            // Do the following explicitly, since we won't be recursing
            // into the LHS global.

            // Note that the type of the expression and the type of the
            // function can actually be *different* due to the NameExpr
            // being constructed based on a forward reference and then
            // the global getting a different (constructed) type when
            // the function is actually declared.  Geez.  So hedge our
            // bets.
            TrackType(n->GetType());
            TrackType(func->GetType());

            TrackID(func);

            return TC_ABORTSTMT;
        }

        case EXPR_EVENT: {
            auto ev = e->AsEventExpr()->Name();
            events.insert(ev);
            addl_hashes.push_back(p_hash(ev));
        } break;

        case EXPR_LAMBDA: {
            auto l = e->AsLambdaExpr();
            lambdas.push_back(l);

            for ( const auto& i : l->OuterIDs() ) {
                locals.insert(i);
                TrackID(i);

                // See above re EXPR_NAME regarding the following
                // logic.
                if ( captures.count(i) == 0 && i->Offset() < num_params )
                    params.insert(i);
            }

            // In general, we don't want to recurse into the body.
            // However, we still want to *profile* it so we can
            // identify calls within it.
            auto pf = std::make_shared<ProfileFunc>(l->Ingredients()->Body().get(), false);
            // func_profs[l->PrimaryFunc()] = pf;
            script_calls.insert(pf->ScriptCalls().begin(), pf->ScriptCalls().end());

            return TC_ABORTSTMT;
        }

        case EXPR_SET_CONSTRUCTOR: {
            auto sc = static_cast<const SetConstructorExpr*>(e);
            const auto& attrs = sc->GetAttrs();

            if ( attrs )
                constructor_attrs[attrs.get()] = sc->GetType();
        } break;

        case EXPR_TABLE_CONSTRUCTOR: {
            auto tc = static_cast<const TableConstructorExpr*>(e);
            const auto& attrs = tc->GetAttrs();

            if ( attrs )
                constructor_attrs[attrs.get()] = tc->GetType();
        } break;

        case EXPR_RECORD_COERCE:
        case EXPR_TABLE_COERCE: {
            auto res_type = e->GetType().get();
            auto orig_type = e->GetOp1()->GetType().get();
            if ( type_aliases.count(res_type) == 0 )
                type_aliases[orig_type] = {res_type};
            else
                type_aliases[orig_type].insert(res_type);
        } break;

        default: break;
    }

    return TC_CONTINUE;
}

TraversalCode ProfileFunc::PreID(const ID* id) {
    TrackID(id);

    // There's no need for any further analysis of this ID.
    return TC_ABORTSTMT;
}

void ProfileFunc::TrackType(const Type* t) {
    if ( ! t )
        return;

    auto [it, inserted] = types.insert(t);

    if ( ! inserted )
        // We've already tracked it.
        return;

    ordered_types.push_back(t);
}

void ProfileFunc::TrackID(const ID* id) {
    if ( ! id )
        return;

    auto [it, inserted] = ids.insert(id);

    if ( ! inserted )
        // Already tracked.
        return;

    ordered_ids.push_back(id);
}

void ProfileFunc::TrackAssignment(const ID* id) {
    if ( assignees.count(id) > 0 )
        ++assignees[id];
    else
        assignees[id] = 1;

    if ( id->IsGlobal() || captures.count(id) > 0 )
        non_local_assignees.insert(id);
}

ProfileFuncs::ProfileFuncs(std::vector<FuncInfo>& funcs, is_compilable_pred pred, bool _full_record_hashes) {
    full_record_hashes = _full_record_hashes;

    for ( auto& f : funcs ) {
        auto pf = std::make_shared<ProfileFunc>(f.Func(), f.Body(), full_record_hashes);

        if ( ! pred || (*pred)(pf.get(), nullptr) )
            MergeInProfile(pf.get());

        // Track the profile even if we're not compiling the function, since
        // the AST optimizer will still need it to reason about function-call
        // side effects.
        f.SetProfile(std::move(pf));
        func_profs[f.Func()] = f.ProfilePtr();
    }

    // We now have the main (starting) types used by all of the
    // functions.  Recursively compute their hashes.
    ComputeTypeHashes(main_types);

    do {
        // Computing the hashes can have marked expressions (seen in
        // record attributes) for further analysis.  Likewise, when
        // doing the profile merges above we may have noted lambda
        // expressions.  Analyze these, and iteratively any further
        // expressions that the analysis uncovers.
        DrainPendingExprs();

        // We now have all the information we need to form definitive,
        // deterministic hashes.
        ComputeBodyHashes(funcs);

        // Computing those hashes could have led to traversals that
        // create more pending expressions to analyze.
    } while ( ! pending_exprs.empty() );

    ComputeSideEffects();
}

void ProfileFuncs::MergeInProfile(ProfileFunc* pf) {
    all_globals.insert(pf->AllGlobals().begin(), pf->AllGlobals().end());

    for ( auto& g : pf->Globals() ) {
        auto [it, inserted] = globals.emplace(g);

        if ( ! inserted )
            continue;

        TraverseValue(g->GetVal());

        const auto& t = g->GetType();
        if ( t->Tag() == TYPE_TYPE )
            (void)HashType(t->AsTypeType()->GetType());

        auto& init_exprs = g->GetOptInfo()->GetInitExprs();
        for ( const auto& i_e : init_exprs )
            if ( i_e ) {
                pending_exprs.push_back(i_e.get());

                if ( i_e->Tag() == EXPR_LAMBDA )
                    lambdas.insert(i_e->AsLambdaExpr());
            }

        auto& attrs = g->GetAttrs();
        if ( attrs )
            AnalyzeAttrs(attrs.get(), t.get());
    }

    constants.insert(pf->Constants().begin(), pf->Constants().end());
    main_types.insert(main_types.end(), pf->OrderedTypes().begin(), pf->OrderedTypes().end());
    script_calls.insert(pf->ScriptCalls().begin(), pf->ScriptCalls().end());
    BiF_globals.insert(pf->BiFGlobals().begin(), pf->BiFGlobals().end());
    events.insert(pf->Events().begin(), pf->Events().end());

    for ( auto& i : pf->Lambdas() ) {
        lambdas.insert(i);
        pending_exprs.push_back(i);
    }

    for ( auto& a : pf->ConstructorAttrs() )
        AnalyzeAttrs(a.first, a.second.get());

    for ( auto& ta : pf->TypeAliases() ) {
        if ( type_aliases.count(ta.first) == 0 )
            type_aliases[ta.first] = std::set<const Type*>{};
        type_aliases[ta.first].insert(ta.second.begin(), ta.second.end());
    }
}

void ProfileFuncs::TraverseValue(const ValPtr& v) {
    if ( ! v )
        return;

    const auto& t = v->GetType();
    (void)HashType(t);

    switch ( t->Tag() ) {
        case TYPE_ADDR:
        case TYPE_ANY:
        case TYPE_BOOL:
        case TYPE_COUNT:
        case TYPE_DOUBLE:
        case TYPE_ENUM:
        case TYPE_ERROR:
        case TYPE_FILE:
        case TYPE_FUNC:
        case TYPE_INT:
        case TYPE_INTERVAL:
        case TYPE_OPAQUE:
        case TYPE_PATTERN:
        case TYPE_PORT:
        case TYPE_STRING:
        case TYPE_SUBNET:
        case TYPE_TIME:
        case TYPE_VOID: break;

        case TYPE_RECORD: {
            auto r = cast_intrusive<RecordVal>(v);
            auto n = r->NumFields();

            for ( auto i = 0u; i < n; ++i )
                TraverseValue(r->GetField(i));
        } break;

        case TYPE_TABLE: {
            auto tv = cast_intrusive<TableVal>(v);
            auto tv_map = tv->ToMap();

            for ( auto& tv_i : tv_map ) {
                TraverseValue(tv_i.first);
                TraverseValue(tv_i.second);
            }
        } break;

        case TYPE_LIST: {
            auto lv = cast_intrusive<ListVal>(v);
            auto n = lv->Length();

            for ( auto i = 0; i < n; ++i )
                TraverseValue(lv->Idx(i));
        } break;

        case TYPE_VECTOR: {
            auto vv = cast_intrusive<VectorVal>(v);
            auto n = vv->Size();

            for ( auto i = 0u; i < n; ++i )
                TraverseValue(vv->ValAt(i));
        } break;

        case TYPE_TYPE: (void)HashType(t->AsTypeType()->GetType()); break;
    }
}

void ProfileFuncs::DrainPendingExprs() {
    while ( pending_exprs.size() > 0 ) {
        // Copy the pending expressions so we can loop over them
        // while accruing additions.
        auto pe = pending_exprs;
        pending_exprs.clear();

        for ( auto e : pe ) {
            auto pf = std::make_shared<ProfileFunc>(e, full_record_hashes);

            expr_profs[e] = pf;
            MergeInProfile(pf.get());

            // It's important to compute the hashes over the
            // ordered types rather than the unordered.  If type
            // T1 depends on a recursive type T2, then T1's hash
            // will vary with depending on whether we arrive at
            // T1 via an in-progress traversal of T2 (in which
            // case T1 will see the "stub" in-progress hash for
            // T2), or via a separate type T3 (in which case it
            // will see the full hash).
            ComputeTypeHashes(pf->OrderedTypes());
        }
    }
}

void ProfileFuncs::ComputeTypeHashes(const std::vector<const Type*>& types) {
    for ( auto t : types )
        (void)HashType(t);
}

void ProfileFuncs::ComputeBodyHashes(std::vector<FuncInfo>& funcs) {
    for ( auto& f : funcs )
        if ( ! f.ShouldSkip() )
            ComputeProfileHash(f.ProfilePtr());

    for ( auto& l : lambdas ) {
        auto pf = ExprProf(l);
        func_profs[l->PrimaryFunc().get()] = pf;
        ComputeProfileHash(pf);
    }
}

void ProfileFuncs::ComputeProfileHash(std::shared_ptr<ProfileFunc> pf) {
    p_hash_type h = 0;

    // We add markers between each class of hash component, to
    // prevent collisions due to elements with simple hashes
    // (such as Stmt's or Expr's that are only represented by
    // the hash of their tag).
    h = merge_p_hashes(h, p_hash("stmts"));
    for ( auto i : pf->Stmts() )
        h = merge_p_hashes(h, p_hash(i->Tag()));

    h = merge_p_hashes(h, p_hash("exprs"));
    for ( auto i : pf->Exprs() )
        h = merge_p_hashes(h, p_hash(i->Tag()));

    h = merge_p_hashes(h, p_hash("ids"));
    for ( auto i : pf->OrderedIdentifiers() )
        h = merge_p_hashes(h, p_hash(i->Name()));

    h = merge_p_hashes(h, p_hash("constants"));
    for ( auto i : pf->Constants() )
        h = merge_p_hashes(h, p_hash(i->Value()));

    h = merge_p_hashes(h, p_hash("types"));
    for ( auto i : pf->OrderedTypes() )
        h = merge_p_hashes(h, HashType(i));

    h = merge_p_hashes(h, p_hash("lambdas"));
    for ( auto i : pf->Lambdas() )
        h = merge_p_hashes(h, p_hash(i));

    h = merge_p_hashes(h, p_hash("addl"));
    for ( auto i : pf->AdditionalHashes() )
        h = merge_p_hashes(h, i);

    pf->SetHashVal(h);
}

p_hash_type ProfileFuncs::HashType(const Type* t) {
    if ( ! t )
        return 0;

    auto it = type_hashes.find(t);

    if ( it != type_hashes.end() )
        // We've already done this Type*.
        return it->second;

    auto& tn = t->GetName();
    if ( ! tn.empty() ) {
        auto seen_it = seen_type_names.find(tn);

        if ( seen_it != seen_type_names.end() ) {
            // We've already done a type with the same name, even
            // though with a different Type*.  Reuse its results.
            auto seen_t = seen_it->second;
            auto h = type_hashes[seen_t];

            type_hashes[t] = h;
            type_to_rep[t] = type_to_rep[seen_t];

            return h;
        }
    }

    auto h = p_hash(t->Tag());
    if ( ! tn.empty() )
        h = merge_p_hashes(h, p_hash(tn));

    // Enter an initial value for this type's hash.  We'll update it
    // at the end, but having it here first will prevent recursive
    // records from leading to infinite recursion as we traverse them.
    // It's okay that the initial value is degenerate, because if we access
    // it during the traversal that will only happen due to a recursive
    // type, in which case the other elements of that type will serve
    // to differentiate its hash.
    type_hashes[t] = h;

    switch ( t->Tag() ) {
        case TYPE_ADDR:
        case TYPE_ANY:
        case TYPE_BOOL:
        case TYPE_COUNT:
        case TYPE_DOUBLE:
        case TYPE_ENUM:
        case TYPE_ERROR:
        case TYPE_INT:
        case TYPE_INTERVAL:
        case TYPE_OPAQUE:
        case TYPE_PATTERN:
        case TYPE_PORT:
        case TYPE_STRING:
        case TYPE_SUBNET:
        case TYPE_TIME:
        case TYPE_VOID: h = merge_p_hashes(h, p_hash(t)); break;

        case TYPE_RECORD: {
            const auto& ft = t->AsRecordType();
            auto n = ft->NumFields();
            auto orig_n = ft->NumOrigFields();

            h = merge_p_hashes(h, p_hash("record"));

            if ( full_record_hashes )
                h = merge_p_hashes(h, p_hash(n));
            else
                h = merge_p_hashes(h, p_hash(orig_n));

            for ( auto i = 0; i < n; ++i ) {
                bool do_hash = full_record_hashes;
                if ( ! do_hash )
                    do_hash = (i < orig_n);

                const auto& f = ft->FieldDecl(i);
                auto type_h = HashType(f->type);

                if ( do_hash ) {
                    h = merge_p_hashes(h, p_hash(f->id));
                    h = merge_p_hashes(h, type_h);
                }

                h = merge_p_hashes(h, p_hash(f->id));
                h = merge_p_hashes(h, HashType(f->type));

                // We don't hash the field name, as in some contexts
                // those are ignored.

                if ( f->attrs ) {
                    if ( do_hash )
                        h = merge_p_hashes(h, HashAttrs(f->attrs));
                    AnalyzeAttrs(f->attrs.get(), t, i);
                }
            }
        } break;

        case TYPE_TABLE: {
            auto tbl = t->AsTableType();
            h = merge_p_hashes(h, p_hash("table"));
            h = merge_p_hashes(h, p_hash("indices"));
            h = merge_p_hashes(h, HashType(tbl->GetIndices()));
            h = merge_p_hashes(h, p_hash("tbl-yield"));
            h = merge_p_hashes(h, HashType(tbl->Yield()));
        } break;

        case TYPE_FUNC: {
            auto ft = t->AsFuncType();
            auto flv = ft->FlavorString();
            h = merge_p_hashes(h, p_hash(flv));

            // We deal with the parameters individually, rather than just
            // recursing into the RecordType that's used (for convenience)
            // to represent them. We do so because their properties are
            // somewhat different - in particular, an &default on a parameter
            // field is resolved in the context of the caller, not the
            // function itself, and so we don't want to track those as
            // attributes associated with the function body's execution.
            h = merge_p_hashes(h, p_hash("params"));
            auto params = ft->Params()->Types();

            if ( params ) {
                h = merge_p_hashes(h, p_hash(params->length()));

                for ( auto p : *params )
                    h = merge_p_hashes(h, HashType(p->type));
            }

            h = merge_p_hashes(h, p_hash("func-yield"));
            h = merge_p_hashes(h, HashType(ft->Yield()));
        } break;

        case TYPE_LIST: {
            auto& tl = t->AsTypeList()->GetTypes();

            h = merge_p_hashes(h, p_hash("list"));
            h = merge_p_hashes(h, p_hash(tl.size()));

            for ( const auto& tl_i : tl )
                h = merge_p_hashes(h, HashType(tl_i));
        } break;

        case TYPE_VECTOR:
            h = merge_p_hashes(h, p_hash("vec"));
            h = merge_p_hashes(h, HashType(t->AsVectorType()->Yield()));
            break;

        case TYPE_FILE:
            h = merge_p_hashes(h, p_hash("file"));
            h = merge_p_hashes(h, HashType(t->AsFileType()->Yield()));
            break;

        case TYPE_TYPE:
            h = merge_p_hashes(h, p_hash("type"));
            h = merge_p_hashes(h, HashType(t->AsTypeType()->GetType()));
            break;
    }

    type_hashes[t] = h;

    auto [rep_it, rep_inserted] = type_hash_reps.emplace(h, t);

    if ( rep_inserted ) { // No previous rep, so use this Type* for that.
        type_to_rep[t] = t;
        rep_types.push_back(t);
    }
    else
        type_to_rep[t] = rep_it->second;

    if ( ! tn.empty() )
        seen_type_names[tn] = t;

    return h;
}

p_hash_type ProfileFuncs::HashAttrs(const AttributesPtr& Attrs) {
    // It's tempting to just use p_hash, but that won't work
    // if the attributes wind up with extensible records in their
    // descriptions, if we're not doing full record hashes.
    auto attrs = Attrs->GetAttrs();
    p_hash_type h = 0;

    for ( const auto& a : attrs ) {
        h = merge_p_hashes(h, p_hash(a->Tag()));
        auto e = a->GetExpr();

        // We don't try to hash an associated expression, since those
        // can vary in structure due to compilation of elements.  We
        // do though enforce consistency for their types.
        if ( e ) {
            h = merge_p_hashes(h, HashType(e->GetType()));
            h = merge_p_hashes(h, p_hash(e.get()));
        }
    }

    return h;
}

extern const char* attr_name(AttrTag t);

void ProfileFuncs::AnalyzeAttrs(const Attributes* attrs, const Type* t, int field) {
    for ( const auto& a : attrs->GetAttrs() ) {
        auto& e = a->GetExpr();

        if ( ! e )
            continue;

        pending_exprs.push_back(e.get());

        auto prev_ea = expr_attrs.find(a.get());
        if ( prev_ea == expr_attrs.end() )
            expr_attrs[a.get()] = {std::pair<const Type*, int>{t, field}};
        else {
            // Add it if new. This is rare, but can arise due to attributes
            // being shared for example from initializers with a variable
            // itself.
            bool found = false;
            for ( auto ea : prev_ea->second )
                if ( ea.first == t && ea.second == field ) {
                    found = true;
                    break;
                }

            if ( ! found )
                prev_ea->second.emplace_back(std::pair<const Type*, int>{t, field});
        }

        if ( e->Tag() == EXPR_LAMBDA )
            lambdas.insert(e->AsLambdaExpr());

#if 0
        // If this is an attribute that can be triggered by statement/expression
        // execution, then we need to determine any modifications it might make
	// to non-local state.
        auto at = a->Tag();
        if ( at != ATTR_DEFAULT && at != ATTR_DEFAULT_INSERT && at != ATTR_ON_CHANGE )
            continue;

	if ( ! CouldHaveSideEffects(e) )
		continue;

	std::vector<SensitiveType> changes;
	GetExprChangesToLocalState(e, changes);

	if ( ! changes.empty() )
		printf("problematic expr: %s\n", obj_desc(e.get()).c_str());
#endif
    }
}

void ProfileFuncs::ComputeSideEffects() {
    // Computing side effects is an iterative process, because whether
    // a given expression has a side effect can depend on whether it
    // includes accesses to types that have side effects.

    // Step one: assemble a candidate pool of attributes to assess.
    for ( auto& ea : expr_attrs ) {
        // Is this an attribute that can be triggered by
        // statement/expression execution?
        auto a = ea.first;
        auto at = a->Tag();
        if ( at == ATTR_DEFAULT || at == ATTR_DEFAULT_INSERT || at == ATTR_ON_CHANGE ) {
            // Weed out very-common-and-completely-safe expressions.
            if ( ! DefinitelyHasNoSideEffects(a->GetExpr()) )
                candidates.insert(a);
        }
    }

    std::vector<std::shared_ptr<SideEffectsOp>> side_effects;

    while ( ! candidates.empty() ) {
        std::unordered_set<const Attr*> made_decision;

        for ( auto c : candidates ) {
            IDSet non_local_ids;
            std::unordered_set<const Type*> aggrs;
            bool is_unknown = false;

            if ( ! AssessSideEffects(c->GetExpr(), non_local_ids, aggrs, is_unknown) )
                // Can't make a decision yet.
                continue;

            made_decision.insert(c);
            auto& effects_vec = attr_side_effects[c] = std::vector<std::shared_ptr<SideEffectsOp>>{};

            if ( non_local_ids.empty() && aggrs.empty() && ! is_unknown ) {
                printf("%s has no side effects\n", obj_desc(c).c_str());
                // Definitely no side effects.
                continue;
            }

            printf("%s has side effects\n", obj_desc(c).c_str());
            // Track the associated side effects.
            auto at = c->Tag() == ATTR_ON_CHANGE ? SideEffectsOp::WRITE : SideEffectsOp::READ;
            for ( auto& ea : expr_attrs[c] ) {
                auto seo = std::make_shared<SideEffectsOp>(at, ea.first, ea.second);
                seo->AddModNonGlobal(non_local_ids);
                seo->AddModAggrs(aggrs);

                if ( is_unknown )
                    seo->SetUnknownChanges();

                effects_vec.push_back(seo);
                side_effects.push_back(std::move(seo));
            }
        }

        ASSERT(! made_decision.empty());
        for ( auto md : made_decision )
            candidates.erase(md);
    }
}

bool ProfileFuncs::DefinitelyHasNoSideEffects(const ExprPtr& e) const {
    if ( e->Tag() == EXPR_CONST || e->Tag() == EXPR_VECTOR_CONSTRUCTOR )
        return true;

    if ( e->Tag() == EXPR_NAME )
        return e->GetType()->Tag() != TYPE_FUNC;

    auto ep = expr_profs.find(e.get());
    ASSERT(ep != expr_profs.end());

    const auto& pf = ep->second;

    if ( ! pf->NonLocalAssignees().empty() || ! pf->AggrRefs().empty() || ! pf->AggrMods().empty() ||
         ! pf->ScriptCalls().empty() )
        return false;

    for ( auto& b : pf->BiFGlobals() )
        if ( ! is_side_effect_free(b->Name()) )
            return false;

    return true;
}

std::vector<const Attr*> ProfileFuncs::AssociatedAttrs(const Type* t, int f) {
    std::vector<const Attr*> assoc_attrs;

    for ( auto c : candidates )
        for ( auto& ea : expr_attrs[c] )
            for ( auto ta : type_aliases[ea.first] )
                if ( same_type(t, ta) && f == ea.second ) {
                    assoc_attrs.push_back(c);
                    break;
                }

    return assoc_attrs;
}

bool ProfileFuncs::AssessSideEffects(const ExprPtr& e, IDSet& non_local_ids, std::unordered_set<const Type*>& aggrs,
                                     bool& is_unknown) {
    std::shared_ptr<ProfileFunc> pf;

    if ( e->Tag() == EXPR_NAME && e->GetType()->Tag() == TYPE_FUNC ) {
        // This occurs when the expression is itself a function name, and
        // in an attribute context indicates an implicit call.
        auto fid = e->AsNameExpr()->Id();
        auto fv = fid->GetVal();

        if ( ! fv || ! fid->IsConst() ) {
            // The value is unavailable (likely a bug), or might change
            // at run-time.
            is_unknown = true;
            return true;
        }

        auto func = fv->AsFunc();
        if ( func->GetKind() == Func::BUILTIN_FUNC ) {
            if ( ! is_side_effect_free(func->Name()) )
                is_unknown = true;
            return true;
        }

        auto sf = static_cast<ScriptFunc*>(func)->Primary();
        ASSERT(func_profs.count(sf) != 0);
        pf = func_profs[sf];
    }
    else {
        ASSERT(expr_profs.count(e.get()) != 0);
        pf = expr_profs[e.get()];
    }

    return AssessSideEffects(pf.get(), non_local_ids, aggrs, is_unknown);
}

bool ProfileFuncs::AssessSideEffects(const ProfileFunc* pf, IDSet& non_local_ids,
                                     std::unordered_set<const Type*>& aggrs, bool& is_unknown) {
    if ( pf->DoesIndirectCalls() )
        is_unknown = true;

    for ( auto& b : pf->BiFGlobals() )
        if ( ! is_side_effect_free(b->Name()) ) {
            is_unknown = true;
            break;
        }

    IDSet nla;
    std::unordered_set<const Type*> mod_aggrs;

    for ( auto& a : pf->NonLocalAssignees() )
        nla.insert(a);

    for ( auto& r : pf->AggrRefs() )
        if ( ! AssessAggrEffects(SideEffectsOp::READ, r.first, r.second, nla, mod_aggrs, is_unknown) )
            return is_unknown;

    for ( auto& a : pf->AggrMods() )
        if ( ! AssessAggrEffects(SideEffectsOp::WRITE, a, 0, nla, mod_aggrs, is_unknown) )
            return is_unknown;

    for ( auto& f : pf->ScriptCalls() ) {
        auto pff = func_profs[f];
        if ( active_func_profiles.count(pff) > 0 )
            continue;

        active_func_profiles.insert(pff);
        auto a = AssessSideEffects(pff.get(), nla, mod_aggrs, is_unknown);
        active_func_profiles.erase(pff);

        if ( ! a )
            return is_unknown;
    }

    non_local_ids.insert(nla.begin(), nla.end());
    aggrs.insert(mod_aggrs.begin(), mod_aggrs.end());

    return true;
}

bool ProfileFuncs::AssessAggrEffects(SideEffectsOp::AccessType access, const Type* t, int f, IDSet& non_local_ids,
                                     std::unordered_set<const Type*>& aggrs, bool& is_unknown) {
    auto assoc_attrs = AssociatedAttrs(t, f);

    for ( auto a : assoc_attrs ) {
        auto ase = attr_side_effects.find(a);
        if ( ase == attr_side_effects.end() )
            return false;

        for ( auto& se : ase->second ) {
            if ( se->GetAccessType() != access )
                continue;

            if ( se->HasUnknownChanges() ) {
                is_unknown = true;
                return true;
            }

            for ( auto a : se->ModAggrs() )
                aggrs.insert(a);
            for ( auto nl : se->ModNonLocals() )
                non_local_ids.insert(nl);
        }
    }

    return true;
}

} // namespace zeek::detail
