{"payload":{"allShortcutsEnabled":false,"fileTree":{"0x02-Session_authentication/api/v1/auth":{"items":[{"name":"__init__.py","path":"0x02-Session_authentication/api/v1/auth/__init__.py","contentType":"file"},{"name":"auth.py","path":"0x02-Session_authentication/api/v1/auth/auth.py","contentType":"file"},{"name":"basic_auth.py","path":"0x02-Session_authentication/api/v1/auth/basic_auth.py","contentType":"file"},{"name":"session_auth.py","path":"0x02-Session_authentication/api/v1/auth/session_auth.py","contentType":"file"},{"name":"session_db_auth.py","path":"0x02-Session_authentication/api/v1/auth/session_db_auth.py","contentType":"file"},{"name":"session_exp_auth.py","path":"0x02-Session_authentication/api/v1/auth/session_exp_auth.py","contentType":"file"}],"totalCount":6},"0x02-Session_authentication/api/v1":{"items":[{"name":"auth","path":"0x02-Session_authentication/api/v1/auth","contentType":"directory"},{"name":"views","path":"0x02-Session_authentication/api/v1/views","contentType":"directory"},{"name":".DS_Store","path":"0x02-Session_authentication/api/v1/.DS_Store","contentType":"file"},{"name":"__init__.py","path":"0x02-Session_authentication/api/v1/__init__.py","contentType":"file"},{"name":"app.py","path":"0x02-Session_authentication/api/v1/app.py","contentType":"file"}],"totalCount":5},"0x02-Session_authentication/api":{"items":[{"name":"v1","path":"0x02-Session_authentication/api/v1","contentType":"directory"},{"name":".DS_Store","path":"0x02-Session_authentication/api/.DS_Store","contentType":"file"},{"name":"__init__.py","path":"0x02-Session_authentication/api/__init__.py","contentType":"file"}],"totalCount":3},"0x02-Session_authentication":{"items":[{"name":"api","path":"0x02-Session_authentication/api","contentType":"directory"},{"name":"models","path":"0x02-Session_authentication/models","contentType":"directory"},{"name":"README.md","path":"0x02-Session_authentication/README.md","contentType":"file"},{"name":"requirements.txt","path":"0x02-Session_authentication/requirements.txt","contentType":"file"}],"totalCount":4},"":{"items":[{"name":"0x00-personal_data","path":"0x00-personal_data","contentType":"directory"},{"name":"0x01-Basic_authentication","path":"0x01-Basic_authentication","contentType":"directory"},{"name":"0x02-Session_authentication","path":"0x02-Session_authentication","contentType":"directory"},{"name":"0x03-user_authentication_service","path":"0x03-user_authentication_service","contentType":"directory"},{"name":"README.md","path":"README.md","contentType":"file"}],"totalCount":5}},"fileTreeProcessingTime":5.434477,"foldersToFetch":[],"repo":{"id":754171861,"defaultBranch":"main","name":"alx-backend-user-data","ownerLogin":"Blackhat-red-team","currentUserCanPush":false,"isFork":false,"isEmpty":false,"createdAt":"2024-02-07T14:40:17.000Z","ownerAvatar":"https://avatars.githubusercontent.com/u/75793444?v=4","public":true,"private":false,"isOrgOwned":false},"symbolsExpanded":false,"treeExpanded":true,"refInfo":{"name":"main","listCacheKey":"v0:1707323455.0","canEdit":false,"refType":"branch","currentOid":"90d29837c9f6caf1e0cffaecbe3385240c0a23f1"},"path":"0x02-Session_authentication/api/v1/auth/session_db_auth.py","currentUser":null,"blob":{"rawLines":["#!/usr/bin/env python3","\"\"\"Session authentication with expiration","and storage support module for the API.","\"\"\"","from flask import request","from datetime import datetime, timedelta","","from models.user_session import UserSession","from .session_exp_auth import SessionExpAuth","","","class SessionDBAuth(SessionExpAuth):","    \"\"\"Session authentication class with expiration and storage support.","    \"\"\"","","    def create_session(self, user_id=None) -> str:","        \"\"\"Creates and stores a session id for the user.","        \"\"\"","        session_id = super().create_session(user_id)","        if type(session_id) == str:","            kwargs = {","                'user_id': user_id,","                'session_id': session_id,","            }","            user_session = UserSession(**kwargs)","            user_session.save()","            return session_id","","    def user_id_for_session_id(self, session_id=None):","        \"\"\"Retrieves the user id of the user associated with","        a given session id.","        \"\"\"","        try:","            sessions = UserSession.search({'session_id': session_id})","        except Exception:","            return None","        if len(sessions) <= 0:","            return None","        cur_time = datetime.now()","        time_span = timedelta(seconds=self.session_duration)","        exp_time = sessions[0].created_at + time_span","        if exp_time < cur_time:","            return None","        return sessions[0].user_id","","    def destroy_session(self, request=None) -> bool:","        \"\"\"Destroys an authenticated session.","        \"\"\"","        session_id = self.session_cookie(request)","        try:","            sessions = UserSession.search({'session_id': session_id})","        except Exception:","            return False","        if len(sessions) <= 0:","            return False","        sessions[0].remove()","        return True"],"stylingDirectives":[[{"start":0,"end":22,"cssClass":"pl-c"}],[{"start":0,"end":41,"cssClass":"pl-s"}],[{"start":0,"end":39,"cssClass":"pl-s"}],[{"start":0,"end":3,"cssClass":"pl-s"}],[{"start":0,"end":4,"cssClass":"pl-k"},{"start":5,"end":10,"cssClass":"pl-s1"},{"start":11,"end":17,"cssClass":"pl-k"},{"start":18,"end":25,"cssClass":"pl-s1"}],[{"start":0,"end":4,"cssClass":"pl-k"},{"start":5,"end":13,"cssClass":"pl-s1"},{"start":14,"end":20,"cssClass":"pl-k"},{"start":21,"end":29,"cssClass":"pl-s1"},{"start":31,"end":40,"cssClass":"pl-s1"}],[],[{"start":0,"end":4,"cssClass":"pl-k"},{"start":5,"end":11,"cssClass":"pl-s1"},{"start":12,"end":24,"cssClass":"pl-s1"},{"start":25,"end":31,"cssClass":"pl-k"},{"start":32,"end":43,"cssClass":"pl-v"}],[{"start":0,"end":4,"cssClass":"pl-k"},{"start":6,"end":22,"cssClass":"pl-s1"},{"start":23,"end":29,"cssClass":"pl-k"},{"start":30,"end":44,"cssClass":"pl-v"}],[],[],[{"start":0,"end":5,"cssClass":"pl-k"},{"start":6,"end":19,"cssClass":"pl-v"},{"start":20,"end":34,"cssClass":"pl-v"}],[{"start":4,"end":72,"cssClass":"pl-s"}],[{"start":0,"end":7,"cssClass":"pl-s"}],[],[{"start":4,"end":7,"cssClass":"pl-k"},{"start":8,"end":22,"cssClass":"pl-en"},{"start":23,"end":27,"cssClass":"pl-s1"},{"start":29,"end":36,"cssClass":"pl-s1"},{"start":36,"end":37,"cssClass":"pl-c1"},{"start":37,"end":41,"cssClass":"pl-c1"},{"start":43,"end":45,"cssClass":"pl-c1"},{"start":46,"end":49,"cssClass":"pl-s1"}],[{"start":8,"end":56,"cssClass":"pl-s"}],[{"start":0,"end":11,"cssClass":"pl-s"}],[{"start":8,"end":18,"cssClass":"pl-s1"},{"start":19,"end":20,"cssClass":"pl-c1"},{"start":21,"end":26,"cssClass":"pl-en"},{"start":29,"end":43,"cssClass":"pl-en"},{"start":44,"end":51,"cssClass":"pl-s1"}],[{"start":8,"end":10,"cssClass":"pl-k"},{"start":11,"end":15,"cssClass":"pl-en"},{"start":16,"end":26,"cssClass":"pl-s1"},{"start":28,"end":30,"cssClass":"pl-c1"},{"start":31,"end":34,"cssClass":"pl-s1"}],[{"start":12,"end":18,"cssClass":"pl-s1"},{"start":19,"end":20,"cssClass":"pl-c1"}],[{"start":16,"end":25,"cssClass":"pl-s"},{"start":27,"end":34,"cssClass":"pl-s1"}],[{"start":16,"end":28,"cssClass":"pl-s"},{"start":30,"end":40,"cssClass":"pl-s1"}],[],[{"start":12,"end":24,"cssClass":"pl-s1"},{"start":25,"end":26,"cssClass":"pl-c1"},{"start":27,"end":38,"cssClass":"pl-v"},{"start":39,"end":41,"cssClass":"pl-c1"},{"start":41,"end":47,"cssClass":"pl-s1"}],[{"start":12,"end":24,"cssClass":"pl-s1"},{"start":25,"end":29,"cssClass":"pl-en"}],[{"start":12,"end":18,"cssClass":"pl-k"},{"start":19,"end":29,"cssClass":"pl-s1"}],[],[{"start":4,"end":7,"cssClass":"pl-k"},{"start":8,"end":30,"cssClass":"pl-en"},{"start":31,"end":35,"cssClass":"pl-s1"},{"start":37,"end":47,"cssClass":"pl-s1"},{"start":47,"end":48,"cssClass":"pl-c1"},{"start":48,"end":52,"cssClass":"pl-c1"}],[{"start":8,"end":60,"cssClass":"pl-s"}],[{"start":0,"end":27,"cssClass":"pl-s"}],[{"start":0,"end":11,"cssClass":"pl-s"}],[{"start":8,"end":11,"cssClass":"pl-k"}],[{"start":12,"end":20,"cssClass":"pl-s1"},{"start":21,"end":22,"cssClass":"pl-c1"},{"start":23,"end":34,"cssClass":"pl-v"},{"start":35,"end":41,"cssClass":"pl-en"},{"start":43,"end":55,"cssClass":"pl-s"},{"start":57,"end":67,"cssClass":"pl-s1"}],[{"start":8,"end":14,"cssClass":"pl-k"},{"start":15,"end":24,"cssClass":"pl-v"}],[{"start":12,"end":18,"cssClass":"pl-k"},{"start":19,"end":23,"cssClass":"pl-c1"}],[{"start":8,"end":10,"cssClass":"pl-k"},{"start":11,"end":14,"cssClass":"pl-en"},{"start":15,"end":23,"cssClass":"pl-s1"},{"start":25,"end":27,"cssClass":"pl-c1"},{"start":28,"end":29,"cssClass":"pl-c1"}],[{"start":12,"end":18,"cssClass":"pl-k"},{"start":19,"end":23,"cssClass":"pl-c1"}],[{"start":8,"end":16,"cssClass":"pl-s1"},{"start":17,"end":18,"cssClass":"pl-c1"},{"start":19,"end":27,"cssClass":"pl-s1"},{"start":28,"end":31,"cssClass":"pl-en"}],[{"start":8,"end":17,"cssClass":"pl-s1"},{"start":18,"end":19,"cssClass":"pl-c1"},{"start":20,"end":29,"cssClass":"pl-en"},{"start":30,"end":37,"cssClass":"pl-s1"},{"start":37,"end":38,"cssClass":"pl-c1"},{"start":38,"end":42,"cssClass":"pl-s1"},{"start":43,"end":59,"cssClass":"pl-s1"}],[{"start":8,"end":16,"cssClass":"pl-s1"},{"start":17,"end":18,"cssClass":"pl-c1"},{"start":19,"end":27,"cssClass":"pl-s1"},{"start":28,"end":29,"cssClass":"pl-c1"},{"start":31,"end":41,"cssClass":"pl-s1"},{"start":42,"end":43,"cssClass":"pl-c1"},{"start":44,"end":53,"cssClass":"pl-s1"}],[{"start":8,"end":10,"cssClass":"pl-k"},{"start":11,"end":19,"cssClass":"pl-s1"},{"start":20,"end":21,"cssClass":"pl-c1"},{"start":22,"end":30,"cssClass":"pl-s1"}],[{"start":12,"end":18,"cssClass":"pl-k"},{"start":19,"end":23,"cssClass":"pl-c1"}],[{"start":8,"end":14,"cssClass":"pl-k"},{"start":15,"end":23,"cssClass":"pl-s1"},{"start":24,"end":25,"cssClass":"pl-c1"},{"start":27,"end":34,"cssClass":"pl-s1"}],[],[{"start":4,"end":7,"cssClass":"pl-k"},{"start":8,"end":23,"cssClass":"pl-en"},{"start":24,"end":28,"cssClass":"pl-s1"},{"start":30,"end":37,"cssClass":"pl-s1"},{"start":37,"end":38,"cssClass":"pl-c1"},{"start":38,"end":42,"cssClass":"pl-c1"},{"start":44,"end":46,"cssClass":"pl-c1"},{"start":47,"end":51,"cssClass":"pl-s1"}],[{"start":8,"end":45,"cssClass":"pl-s"}],[{"start":0,"end":11,"cssClass":"pl-s"}],[{"start":8,"end":18,"cssClass":"pl-s1"},{"start":19,"end":20,"cssClass":"pl-c1"},{"start":21,"end":25,"cssClass":"pl-s1"},{"start":26,"end":40,"cssClass":"pl-en"},{"start":41,"end":48,"cssClass":"pl-s1"}],[{"start":8,"end":11,"cssClass":"pl-k"}],[{"start":12,"end":20,"cssClass":"pl-s1"},{"start":21,"end":22,"cssClass":"pl-c1"},{"start":23,"end":34,"cssClass":"pl-v"},{"start":35,"end":41,"cssClass":"pl-en"},{"start":43,"end":55,"cssClass":"pl-s"},{"start":57,"end":67,"cssClass":"pl-s1"}],[{"start":8,"end":14,"cssClass":"pl-k"},{"start":15,"end":24,"cssClass":"pl-v"}],[{"start":12,"end":18,"cssClass":"pl-k"},{"start":19,"end":24,"cssClass":"pl-c1"}],[{"start":8,"end":10,"cssClass":"pl-k"},{"start":11,"end":14,"cssClass":"pl-en"},{"start":15,"end":23,"cssClass":"pl-s1"},{"start":25,"end":27,"cssClass":"pl-c1"},{"start":28,"end":29,"cssClass":"pl-c1"}],[{"start":12,"end":18,"cssClass":"pl-k"},{"start":19,"end":24,"cssClass":"pl-c1"}],[{"start":8,"end":16,"cssClass":"pl-s1"},{"start":17,"end":18,"cssClass":"pl-c1"},{"start":20,"end":26,"cssClass":"pl-en"}],[{"start":8,"end":14,"cssClass":"pl-k"},{"start":15,"end":19,"cssClass":"pl-c1"}]],"csv":null,"csvError":null,"dependabotInfo":{"showConfigurationBanner":false,"configFilePath":null,"networkDependabotPath":"/Blackhat-red-team/alx-backend-user-data/network/updates","dismissConfigurationNoticePath":"/settings/dismiss-notice/dependabot_configuration_notice","configurationNoticeDismissed":null},"displayName":"session_db_auth.py","displayUrl":"https://github.com/Blackhat-red-team/alx-backend-user-data/blob/main/0x02-Session_authentication/api/v1/auth/session_db_auth.py?raw=true","headerInfo":{"blobSize":"1.77 KB","deleteTooltip":"You must be signed in to make or propose changes","editTooltip":"You must be signed in to make or propose changes","deleteInfo":{"deleteTooltip":"You must be signed in to make or propose changes"},"editInfo":{"editTooltip":"You must be signed in to make or propose changes"},"ghDesktopPath":"https://desktop.github.com","isGitLfs":false,"gitLfsPath":null,"onBranch":true,"shortPath":"d6b8fbc","siteNavLoginPath":"/login?return_to=https%3A%2F%2Fgithub.com%2FBlackhat-red-team%2Falx-backend-user-data%2Fblob%2Fmain%2F0x02-Session_authentication%2Fapi%2Fv1%2Fauth%2Fsession_db_auth.py","isCSV":false,"isRichtext":false,"toc":null,"lineInfo":{"truncatedLoc":"57","truncatedSloc":"51"},"mode":"executable file"},"image":false,"isCodeownersFile":null,"isPlain":false,"isValidLegacyIssueTemplate":false,"issueTemplateHelpUrl":"https://docs.github.com/articles/about-issue-and-pull-request-templates","issueTemplate":null,"discussionTemplate":null,"language":"Python","languageID":303,"large":false,"loggedIn":false,"planSupportInfo":{"repoIsFork":null,"repoOwnedByCurrentUser":null,"requestFullPath":"/Blackhat-red-team/alx-backend-user-data/blob/main/0x02-Session_authentication/api/v1/auth/session_db_auth.py","showFreeOrgGatedFeatureMessage":null,"showPlanSupportBanner":null,"upgradeDataAttributes":null,"upgradePath":null},"publishBannersInfo":{"dismissActionNoticePath":"/settings/dismiss-notice/publish_action_from_dockerfile","releasePath":"/Blackhat-red-team/alx-backend-user-data/releases/new?marketplace=true","showPublishActionBanner":false},"rawBlobUrl":"https://github.com/Blackhat-red-team/alx-backend-user-data/raw/main/0x02-Session_authentication/api/v1/auth/session_db_auth.py","renderImageOrRaw":false,"richText":null,"renderedFileInfo":null,"shortPath":null,"symbolsEnabled":true,"tabSize":8,"topBannersInfo":{"overridingGlobalFundingFile":false,"globalPreferredFundingPath":null,"repoOwner":"Blackhat-red-team","repoName":"alx-backend-user-data","showInvalidCitationWarning":false,"citationHelpUrl":"https://docs.github.com/github/creating-cloning-and-archiving-repositories/creating-a-repository-on-github/about-citation-files","actionsOnboardingTip":null},"truncated":false,"viewable":true,"workflowRedirectUrl":null,"symbols":{"timed_out":false,"not_analyzed":false,"symbols":[{"name":"SessionDBAuth","kind":"class","ident_start":274,"ident_end":287,"extent_start":268,"extent_end":1807,"fully_qualified_name":"SessionDBAuth","ident_utf16":{"start":{"line_number":11,"utf16_col":6},"end":{"line_number":11,"utf16_col":19}},"extent_utf16":{"start":{"line_number":11,"utf16_col":0},"end":{"line_number":56,"utf16_col":19}}},{"name":"create_session","kind":"function","ident_start":395,"ident_end":409,"extent_start":391,"extent_end":821,"fully_qualified_name":"SessionDBAuth.create_session","ident_utf16":{"start":{"line_number":15,"utf16_col":8},"end":{"line_number":15,"utf16_col":22}},"extent_utf16":{"start":{"line_number":15,"utf16_col":4},"end":{"line_number":26,"utf16_col":29}}},{"name":"user_id_for_session_id","kind":"function","ident_start":831,"ident_end":853,"extent_start":827,"extent_end":1406,"fully_qualified_name":"SessionDBAuth.user_id_for_session_id","ident_utf16":{"start":{"line_number":28,"utf16_col":8},"end":{"line_number":28,"utf16_col":30}},"extent_utf16":{"start":{"line_number":28,"utf16_col":4},"end":{"line_number":43,"utf16_col":34}}},{"name":"destroy_session","kind":"function","ident_start":1416,"ident_end":1431,"extent_start":1412,"extent_end":1807,"fully_qualified_name":"SessionDBAuth.destroy_session","ident_utf16":{"start":{"line_number":45,"utf16_col":8},"end":{"line_number":45,"utf16_col":23}},"extent_utf16":{"start":{"line_number":45,"utf16_col":4},"end":{"line_number":56,"utf16_col":19}}}]}},"copilotInfo":null,"copilotAccessAllowed":false,"csrf_tokens":{"/Blackhat-red-team/alx-backend-user-data/branches":{"post":"0GhsYjr6RMZnnS7tU1_gQeRz0S8QPfANaYDicFPNEKa4LwuGRe6RqNezkcH6qCjBDC8Kxc2xBJLpySuB3LdLzA"},"/repos/preferences":{"post":"NUsfg7z6fNpOM_FMbV2SKZ5xczcpKWu3X5ks3J-rLH9VuQBYEvLy0L53-9rtTfJLxrH-NHrh2pPBsBtCkSkchg"}}},"title":"alx-backend-user-data/0x02-Session_authentication/api/v1/auth/session_db_auth.py at main · Blackhat-red-team/alx-backend-user-data"}