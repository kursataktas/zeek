#include "zeek/cluster/BifSupport.h"

#include "zeek/Event.h"
#include "zeek/Frame.h"
#include "zeek/Func.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Reporter.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/cluster/Backend.h"

namespace zeek::cluster::detail::bif {

ScriptLocationScope::ScriptLocationScope(const zeek::detail::Frame* frame) {
    zeek::reporter->PushLocation(frame->GetCallLocation());
}

ScriptLocationScope::~ScriptLocationScope() { zeek::reporter->PopLocation(); }

zeek::ValPtr publish_event(const zeek::ValPtr& topic, zeek::ArgsSpan args) {
    if ( args.empty() ) {
        zeek::emit_builtin_error("no event arguments given");
        return zeek::val_mgr->False();
    }

    if ( topic->GetType()->Tag() != zeek::TYPE_STRING ) {
        zeek::emit_builtin_error("topic is not a string");
        return zeek::val_mgr->False();
    }

    const auto topic_str = topic->AsStringVal()->ToStdString();

    auto timestamp = zeek::event_mgr.CurrentEventTime();

    if ( args[0]->GetType()->Tag() == zeek::TYPE_FUNC ) {
        auto event = zeek::cluster::backend->MakeClusterEvent({zeek::NewRef{}, args[0]->AsFuncVal()}, args.subspan(1),
                                                              timestamp);
        if ( event )
            return zeek::val_mgr->Bool(zeek::cluster::backend->PublishEvent(topic_str, *event));

        return zeek::val_mgr->False();
    }
    else if ( args[0]->GetType()->Tag() == zeek::TYPE_RECORD ) {
        return zeek::val_mgr->Bool(
            zeek::cluster::backend->PublishEvent(topic_str, zeek::cast_intrusive<zeek::RecordVal>(args[0])));
    }

    zeek::emit_builtin_error("publish second argument neither function nor record");
    return zeek::val_mgr->False();
}

bool is_cluster_pool(const zeek::Val* pool) {
    static zeek::RecordTypePtr pool_type = nullptr;

    if ( ! pool_type )
        pool_type = zeek::id::find_type<zeek::RecordType>("Cluster::Pool");

    return pool->GetType() == pool_type;
}
} // namespace zeek::cluster::detail::bif
