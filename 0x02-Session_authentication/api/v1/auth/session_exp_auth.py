{"payload":{"allShortcutsEnabled":false,"fileTree":{"0x02-Session_authentication/api/v1/auth":{"items":[{"name":"__init__.py","path":"0x02-Session_authentication/api/v1/auth/__init__.py","contentType":"file"},{"name":"auth.py","path":"0x02-Session_authentication/api/v1/auth/auth.py","contentType":"file"},{"name":"basic_auth.py","path":"0x02-Session_authentication/api/v1/auth/basic_auth.py","contentType":"file"},{"name":"session_auth.py","path":"0x02-Session_authentication/api/v1/auth/session_auth.py","contentType":"file"},{"name":"session_db_auth.py","path":"0x02-Session_authentication/api/v1/auth/session_db_auth.py","contentType":"file"},{"name":"session_exp_auth.py","path":"0x02-Session_authentication/api/v1/auth/session_exp_auth.py","contentType":"file"}],"totalCount":6},"0x02-Session_authentication/api/v1":{"items":[{"name":"auth","path":"0x02-Session_authentication/api/v1/auth","contentType":"directory"},{"name":"views","path":"0x02-Session_authentication/api/v1/views","contentType":"directory"},{"name":".DS_Store","path":"0x02-Session_authentication/api/v1/.DS_Store","contentType":"file"},{"name":"__init__.py","path":"0x02-Session_authentication/api/v1/__init__.py","contentType":"file"},{"name":"app.py","path":"0x02-Session_authentication/api/v1/app.py","contentType":"file"}],"totalCount":5},"0x02-Session_authentication/api":{"items":[{"name":"v1","path":"0x02-Session_authentication/api/v1","contentType":"directory"},{"name":".DS_Store","path":"0x02-Session_authentication/api/.DS_Store","contentType":"file"},{"name":"__init__.py","path":"0x02-Session_authentication/api/__init__.py","contentType":"file"}],"totalCount":3},"0x02-Session_authentication":{"items":[{"name":"api","path":"0x02-Session_authentication/api","contentType":"directory"},{"name":"models","path":"0x02-Session_authentication/models","contentType":"directory"},{"name":"README.md","path":"0x02-Session_authentication/README.md","contentType":"file"},{"name":"requirements.txt","path":"0x02-Session_authentication/requirements.txt","contentType":"file"}],"totalCount":4},"":{"items":[{"name":"0x00-personal_data","path":"0x00-personal_data","contentType":"directory"},{"name":"0x01-Basic_authentication","path":"0x01-Basic_authentication","contentType":"directory"},{"name":"0x02-Session_authentication","path":"0x02-Session_authentication","contentType":"directory"},{"name":"0x03-user_authentication_service","path":"0x03-user_authentication_service","contentType":"directory"},{"name":"README.md","path":"README.md","contentType":"file"}],"totalCount":5}},"fileTreeProcessingTime":5.38546,"foldersToFetch":[],"repo":{"id":754171861,"defaultBranch":"main","name":"alx-backend-user-data","ownerLogin":"Blackhat-red-team","currentUserCanPush":false,"isFork":false,"isEmpty":false,"createdAt":"2024-02-07T14:40:17.000Z","ownerAvatar":"https://avatars.githubusercontent.com/u/75793444?v=4","public":true,"private":false,"isOrgOwned":false},"symbolsExpanded":false,"treeExpanded":true,"refInfo":{"name":"main","listCacheKey":"v0:1707323455.0","canEdit":false,"refType":"branch","currentOid":"90d29837c9f6caf1e0cffaecbe3385240c0a23f1"},"path":"0x02-Session_authentication/api/v1/auth/session_exp_auth.py","currentUser":null,"blob":{"rawLines":["#!/usr/bin/env python3","\"\"\"Session authentication with expiration module for the API.","\"\"\"","import os","from flask import request","from datetime import datetime, timedelta","","from .session_auth import SessionAuth","","","class SessionExpAuth(SessionAuth):","    \"\"\"Session authentication class with expiration.","    \"\"\"","","    def __init__(self) -> None:","        \"\"\"Initializes a new SessionExpAuth instance.","        \"\"\"","        super().__init__()","        try:","            self.session_duration = int(os.getenv('SESSION_DURATION', '0'))","        except Exception:","            self.session_duration = 0","","    def create_session(self, user_id=None):","        \"\"\"Creates a session id for the user.","        \"\"\"","        session_id = super().create_session(user_id)","        if type(session_id) != str:","            return None","        self.user_id_by_session_id[session_id] = {","            'user_id': user_id,","            'created_at': datetime.now(),","        }","        return session_id","","    def user_id_for_session_id(self, session_id=None) -> str:","        \"\"\"Retrieves the user id of the user associated with","        a given session id.","        \"\"\"","        if session_id in self.user_id_by_session_id:","            session_dict = self.user_id_by_session_id[session_id]","            if self.session_duration <= 0:","                return session_dict['user_id']","            if 'created_at' not in session_dict:","                return None","            cur_time = datetime.now()","            time_span = timedelta(seconds=self.session_duration)","            exp_time = session_dict['created_at'] + time_span","            if exp_time < cur_time:","                return None","            return session_dict['user_id']"],"stylingDirectives":[[{"start":0,"end":22,"cssClass":"pl-c"}],[{"start":0,"end":61,"cssClass":"pl-s"}],[{"start":0,"end":3,"cssClass":"pl-s"}],[{"start":0,"end":6,"cssClass":"pl-k"},{"start":7,"end":9,"cssClass":"pl-s1"}],[{"start":0,"end":4,"cssClass":"pl-k"},{"start":5,"end":10,"cssClass":"pl-s1"},{"start":11,"end":17,"cssClass":"pl-k"},{"start":18,"end":25,"cssClass":"pl-s1"}],[{"start":0,"end":4,"cssClass":"pl-k"},{"start":5,"end":13,"cssClass":"pl-s1"},{"start":14,"end":20,"cssClass":"pl-k"},{"start":21,"end":29,"cssClass":"pl-s1"},{"start":31,"end":40,"cssClass":"pl-s1"}],[],[{"start":0,"end":4,"cssClass":"pl-k"},{"start":6,"end":18,"cssClass":"pl-s1"},{"start":19,"end":25,"cssClass":"pl-k"},{"start":26,"end":37,"cssClass":"pl-v"}],[],[],[{"start":0,"end":5,"cssClass":"pl-k"},{"start":6,"end":20,"cssClass":"pl-v"},{"start":21,"end":32,"cssClass":"pl-v"}],[{"start":4,"end":52,"cssClass":"pl-s"}],[{"start":0,"end":7,"cssClass":"pl-s"}],[],[{"start":4,"end":7,"cssClass":"pl-k"},{"start":8,"end":16,"cssClass":"pl-en"},{"start":17,"end":21,"cssClass":"pl-s1"},{"start":23,"end":25,"cssClass":"pl-c1"},{"start":26,"end":30,"cssClass":"pl-c1"}],[{"start":8,"end":53,"cssClass":"pl-s"}],[{"start":0,"end":11,"cssClass":"pl-s"}],[{"start":8,"end":13,"cssClass":"pl-en"},{"start":16,"end":24,"cssClass":"pl-en"}],[{"start":8,"end":11,"cssClass":"pl-k"}],[{"start":12,"end":16,"cssClass":"pl-s1"},{"start":17,"end":33,"cssClass":"pl-s1"},{"start":34,"end":35,"cssClass":"pl-c1"},{"start":36,"end":39,"cssClass":"pl-en"},{"start":40,"end":42,"cssClass":"pl-s1"},{"start":43,"end":49,"cssClass":"pl-en"},{"start":50,"end":68,"cssClass":"pl-s"},{"start":70,"end":73,"cssClass":"pl-s"}],[{"start":8,"end":14,"cssClass":"pl-k"},{"start":15,"end":24,"cssClass":"pl-v"}],[{"start":12,"end":16,"cssClass":"pl-s1"},{"start":17,"end":33,"cssClass":"pl-s1"},{"start":34,"end":35,"cssClass":"pl-c1"},{"start":36,"end":37,"cssClass":"pl-c1"}],[],[{"start":4,"end":7,"cssClass":"pl-k"},{"start":8,"end":22,"cssClass":"pl-en"},{"start":23,"end":27,"cssClass":"pl-s1"},{"start":29,"end":36,"cssClass":"pl-s1"},{"start":36,"end":37,"cssClass":"pl-c1"},{"start":37,"end":41,"cssClass":"pl-c1"}],[{"start":8,"end":45,"cssClass":"pl-s"}],[{"start":0,"end":11,"cssClass":"pl-s"}],[{"start":8,"end":18,"cssClass":"pl-s1"},{"start":19,"end":20,"cssClass":"pl-c1"},{"start":21,"end":26,"cssClass":"pl-en"},{"start":29,"end":43,"cssClass":"pl-en"},{"start":44,"end":51,"cssClass":"pl-s1"}],[{"start":8,"end":10,"cssClass":"pl-k"},{"start":11,"end":15,"cssClass":"pl-en"},{"start":16,"end":26,"cssClass":"pl-s1"},{"start":28,"end":30,"cssClass":"pl-c1"},{"start":31,"end":34,"cssClass":"pl-s1"}],[{"start":12,"end":18,"cssClass":"pl-k"},{"start":19,"end":23,"cssClass":"pl-c1"}],[{"start":8,"end":12,"cssClass":"pl-s1"},{"start":13,"end":34,"cssClass":"pl-s1"},{"start":35,"end":45,"cssClass":"pl-s1"},{"start":47,"end":48,"cssClass":"pl-c1"}],[{"start":12,"end":21,"cssClass":"pl-s"},{"start":23,"end":30,"cssClass":"pl-s1"}],[{"start":12,"end":24,"cssClass":"pl-s"},{"start":26,"end":34,"cssClass":"pl-s1"},{"start":35,"end":38,"cssClass":"pl-en"}],[],[{"start":8,"end":14,"cssClass":"pl-k"},{"start":15,"end":25,"cssClass":"pl-s1"}],[],[{"start":4,"end":7,"cssClass":"pl-k"},{"start":8,"end":30,"cssClass":"pl-en"},{"start":31,"end":35,"cssClass":"pl-s1"},{"start":37,"end":47,"cssClass":"pl-s1"},{"start":47,"end":48,"cssClass":"pl-c1"},{"start":48,"end":52,"cssClass":"pl-c1"},{"start":54,"end":56,"cssClass":"pl-c1"},{"start":57,"end":60,"cssClass":"pl-s1"}],[{"start":8,"end":60,"cssClass":"pl-s"}],[{"start":0,"end":27,"cssClass":"pl-s"}],[{"start":0,"end":11,"cssClass":"pl-s"}],[{"start":8,"end":10,"cssClass":"pl-k"},{"start":11,"end":21,"cssClass":"pl-s1"},{"start":22,"end":24,"cssClass":"pl-c1"},{"start":25,"end":29,"cssClass":"pl-s1"},{"start":30,"end":51,"cssClass":"pl-s1"}],[{"start":12,"end":24,"cssClass":"pl-s1"},{"start":25,"end":26,"cssClass":"pl-c1"},{"start":27,"end":31,"cssClass":"pl-s1"},{"start":32,"end":53,"cssClass":"pl-s1"},{"start":54,"end":64,"cssClass":"pl-s1"}],[{"start":12,"end":14,"cssClass":"pl-k"},{"start":15,"end":19,"cssClass":"pl-s1"},{"start":20,"end":36,"cssClass":"pl-s1"},{"start":37,"end":39,"cssClass":"pl-c1"},{"start":40,"end":41,"cssClass":"pl-c1"}],[{"start":16,"end":22,"cssClass":"pl-k"},{"start":23,"end":35,"cssClass":"pl-s1"},{"start":36,"end":45,"cssClass":"pl-s"}],[{"start":12,"end":14,"cssClass":"pl-k"},{"start":15,"end":27,"cssClass":"pl-s"},{"start":28,"end":31,"cssClass":"pl-c1"},{"start":32,"end":34,"cssClass":"pl-c1"},{"start":35,"end":47,"cssClass":"pl-s1"}],[{"start":16,"end":22,"cssClass":"pl-k"},{"start":23,"end":27,"cssClass":"pl-c1"}],[{"start":12,"end":20,"cssClass":"pl-s1"},{"start":21,"end":22,"cssClass":"pl-c1"},{"start":23,"end":31,"cssClass":"pl-s1"},{"start":32,"end":35,"cssClass":"pl-en"}],[{"start":12,"end":21,"cssClass":"pl-s1"},{"start":22,"end":23,"cssClass":"pl-c1"},{"start":24,"end":33,"cssClass":"pl-en"},{"start":34,"end":41,"cssClass":"pl-s1"},{"start":41,"end":42,"cssClass":"pl-c1"},{"start":42,"end":46,"cssClass":"pl-s1"},{"start":47,"end":63,"cssClass":"pl-s1"}],[{"start":12,"end":20,"cssClass":"pl-s1"},{"start":21,"end":22,"cssClass":"pl-c1"},{"start":23,"end":35,"cssClass":"pl-s1"},{"start":36,"end":48,"cssClass":"pl-s"},{"start":50,"end":51,"cssClass":"pl-c1"},{"start":52,"end":61,"cssClass":"pl-s1"}],[{"start":12,"end":14,"cssClass":"pl-k"},{"start":15,"end":23,"cssClass":"pl-s1"},{"start":24,"end":25,"cssClass":"pl-c1"},{"start":26,"end":34,"cssClass":"pl-s1"}],[{"start":16,"end":22,"cssClass":"pl-k"},{"start":23,"end":27,"cssClass":"pl-c1"}],[{"start":12,"end":18,"cssClass":"pl-k"},{"start":19,"end":31,"cssClass":"pl-s1"},{"start":32,"end":41,"cssClass":"pl-s"}]],"csv":null,"csvError":null,"dependabotInfo":{"showConfigurationBanner":false,"configFilePath":null,"networkDependabotPath":"/Blackhat-red-team/alx-backend-user-data/network/updates","dismissConfigurationNoticePath":"/settings/dismiss-notice/dependabot_configuration_notice","configurationNoticeDismissed":null},"displayName":"session_exp_auth.py","displayUrl":"https://github.com/Blackhat-red-team/alx-backend-user-data/blob/main/0x02-Session_authentication/api/v1/auth/session_exp_auth.py?raw=true","headerInfo":{"blobSize":"1.64 KB","deleteTooltip":"You must be signed in to make or propose changes","editTooltip":"You must be signed in to make or propose changes","deleteInfo":{"deleteTooltip":"You must be signed in to make or propose changes"},"editInfo":{"editTooltip":"You must be signed in to make or propose changes"},"ghDesktopPath":"https://desktop.github.com","isGitLfs":false,"gitLfsPath":null,"onBranch":true,"shortPath":"e635343","siteNavLoginPath":"/login?return_to=https%3A%2F%2Fgithub.com%2FBlackhat-red-team%2Falx-backend-user-data%2Fblob%2Fmain%2F0x02-Session_authentication%2Fapi%2Fv1%2Fauth%2Fsession_exp_auth.py","isCSV":false,"isRichtext":false,"toc":null,"lineInfo":{"truncatedLoc":"51","truncatedSloc":"45"},"mode":"executable file"},"image":false,"isCodeownersFile":null,"isPlain":false,"isValidLegacyIssueTemplate":false,"issueTemplateHelpUrl":"https://docs.github.com/articles/about-issue-and-pull-request-templates","issueTemplate":null,"discussionTemplate":null,"language":"Python","languageID":303,"large":false,"loggedIn":false,"planSupportInfo":{"repoIsFork":null,"repoOwnedByCurrentUser":null,"requestFullPath":"/Blackhat-red-team/alx-backend-user-data/blob/main/0x02-Session_authentication/api/v1/auth/session_exp_auth.py","showFreeOrgGatedFeatureMessage":null,"showPlanSupportBanner":null,"upgradeDataAttributes":null,"upgradePath":null},"publishBannersInfo":{"dismissActionNoticePath":"/settings/dismiss-notice/publish_action_from_dockerfile","releasePath":"/Blackhat-red-team/alx-backend-user-data/releases/new?marketplace=true","showPublishActionBanner":false},"rawBlobUrl":"https://github.com/Blackhat-red-team/alx-backend-user-data/raw/main/0x02-Session_authentication/api/v1/auth/session_exp_auth.py","renderImageOrRaw":false,"richText":null,"renderedFileInfo":null,"shortPath":null,"symbolsEnabled":true,"tabSize":8,"topBannersInfo":{"overridingGlobalFundingFile":false,"globalPreferredFundingPath":null,"repoOwner":"Blackhat-red-team","repoName":"alx-backend-user-data","showInvalidCitationWarning":false,"citationHelpUrl":"https://docs.github.com/github/creating-cloning-and-archiving-repositories/creating-a-repository-on-github/about-citation-files","actionsOnboardingTip":null},"truncated":false,"viewable":true,"workflowRedirectUrl":null,"symbols":{"timed_out":false,"not_analyzed":false,"symbols":[{"name":"SessionExpAuth","kind":"class","ident_start":213,"ident_end":227,"extent_start":207,"extent_end":1680,"fully_qualified_name":"SessionExpAuth","ident_utf16":{"start":{"line_number":10,"utf16_col":6},"end":{"line_number":10,"utf16_col":20}},"extent_utf16":{"start":{"line_number":10,"utf16_col":0},"end":{"line_number":50,"utf16_col":42}}},{"name":"__init__","kind":"function","ident_start":312,"ident_end":320,"extent_start":308,"extent_end":581,"fully_qualified_name":"SessionExpAuth.__init__","ident_utf16":{"start":{"line_number":14,"utf16_col":8},"end":{"line_number":14,"utf16_col":16}},"extent_utf16":{"start":{"line_number":14,"utf16_col":4},"end":{"line_number":21,"utf16_col":37}}},{"name":"create_session","kind":"function","ident_start":591,"ident_end":605,"extent_start":587,"extent_end":958,"fully_qualified_name":"SessionExpAuth.create_session","ident_utf16":{"start":{"line_number":23,"utf16_col":8},"end":{"line_number":23,"utf16_col":22}},"extent_utf16":{"start":{"line_number":23,"utf16_col":4},"end":{"line_number":33,"utf16_col":25}}},{"name":"user_id_for_session_id","kind":"function","ident_start":968,"ident_end":990,"extent_start":964,"extent_end":1680,"fully_qualified_name":"SessionExpAuth.user_id_for_session_id","ident_utf16":{"start":{"line_number":35,"utf16_col":8},"end":{"line_number":35,"utf16_col":30}},"extent_utf16":{"start":{"line_number":35,"utf16_col":4},"end":{"line_number":50,"utf16_col":42}}}]}},"copilotInfo":null,"copilotAccessAllowed":false,"csrf_tokens":{"/Blackhat-red-team/alx-backend-user-data/branches":{"post":"ddrFDaYmzdZgKPAf-7xJ5kB-uiJcFIPvAwdcLeBXWED0lPHuaCgv28VNeTL47whNrx8LbAqigE8vBy1tJZr6ZA"},"/repos/preferences":{"post":"37MtOAKcepEdK3H-3PIgytWHwnNU4B7i__p1d2WgsVpAy4xULDXOjifH-BoVkG90_f6oOjAQvW5wZ5Tv3uFBig"}}},"title":"alx-backend-user-data/0x02-Session_authentication/api/v1/auth/session_exp_auth.py at main · Blackhat-red-team/alx-backend-user-data"}