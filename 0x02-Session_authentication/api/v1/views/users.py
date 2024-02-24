{"payload":{"allShortcutsEnabled":false,"fileTree":{"0x02-Session_authentication/api/v1/views":{"items":[{"name":".DS_Store","path":"0x02-Session_authentication/api/v1/views/.DS_Store","contentType":"file"},{"name":"__init__.py","path":"0x02-Session_authentication/api/v1/views/__init__.py","contentType":"file"},{"name":"index.py","path":"0x02-Session_authentication/api/v1/views/index.py","contentType":"file"},{"name":"session_auth.py","path":"0x02-Session_authentication/api/v1/views/session_auth.py","contentType":"file"},{"name":"users.py","path":"0x02-Session_authentication/api/v1/views/users.py","contentType":"file"}],"totalCount":5},"0x02-Session_authentication/api/v1":{"items":[{"name":"auth","path":"0x02-Session_authentication/api/v1/auth","contentType":"directory"},{"name":"views","path":"0x02-Session_authentication/api/v1/views","contentType":"directory"},{"name":".DS_Store","path":"0x02-Session_authentication/api/v1/.DS_Store","contentType":"file"},{"name":"__init__.py","path":"0x02-Session_authentication/api/v1/__init__.py","contentType":"file"},{"name":"app.py","path":"0x02-Session_authentication/api/v1/app.py","contentType":"file"}],"totalCount":5},"0x02-Session_authentication/api":{"items":[{"name":"v1","path":"0x02-Session_authentication/api/v1","contentType":"directory"},{"name":".DS_Store","path":"0x02-Session_authentication/api/.DS_Store","contentType":"file"},{"name":"__init__.py","path":"0x02-Session_authentication/api/__init__.py","contentType":"file"}],"totalCount":3},"0x02-Session_authentication":{"items":[{"name":"api","path":"0x02-Session_authentication/api","contentType":"directory"},{"name":"models","path":"0x02-Session_authentication/models","contentType":"directory"},{"name":"README.md","path":"0x02-Session_authentication/README.md","contentType":"file"},{"name":"requirements.txt","path":"0x02-Session_authentication/requirements.txt","contentType":"file"}],"totalCount":4},"":{"items":[{"name":"0x00-personal_data","path":"0x00-personal_data","contentType":"directory"},{"name":"0x01-Basic_authentication","path":"0x01-Basic_authentication","contentType":"directory"},{"name":"0x02-Session_authentication","path":"0x02-Session_authentication","contentType":"directory"},{"name":"0x03-user_authentication_service","path":"0x03-user_authentication_service","contentType":"directory"},{"name":"README.md","path":"README.md","contentType":"file"}],"totalCount":5}},"fileTreeProcessingTime":5.448173,"foldersToFetch":[],"repo":{"id":754171861,"defaultBranch":"main","name":"alx-backend-user-data","ownerLogin":"Blackhat-red-team","currentUserCanPush":false,"isFork":false,"isEmpty":false,"createdAt":"2024-02-07T14:40:17.000Z","ownerAvatar":"https://avatars.githubusercontent.com/u/75793444?v=4","public":true,"private":false,"isOrgOwned":false},"symbolsExpanded":false,"treeExpanded":true,"refInfo":{"name":"main","listCacheKey":"v0:1707323455.0","canEdit":false,"refType":"branch","currentOid":"90d29837c9f6caf1e0cffaecbe3385240c0a23f1"},"path":"0x02-Session_authentication/api/v1/views/users.py","currentUser":null,"blob":{"rawLines":["#!/usr/bin/env python3","\"\"\"Module of Users views.","\"\"\"","from api.v1.views import app_views","from flask import abort, jsonify, request","from models.user import User","","","@app_views.route('/users', methods=['GET'], strict_slashes=False)","def view_all_users() -> str:","    \"\"\"GET /api/v1/users","    Return:","      - list of all User objects JSON represented.","    \"\"\"","    all_users = [user.to_json() for user in User.all()]","    return jsonify(all_users)","","","@app_views.route('/users/<user_id>', methods=['GET'], strict_slashes=False)","def view_one_user(user_id: str = None) -> str:","    \"\"\"GET /api/v1/users/:id","    Path parameter:","      - User ID.","    Return:","      - User object JSON represented.","      - 404 if the User ID doesn't exist.","    \"\"\"","    if user_id is None:","        abort(404)","    if user_id == 'me':","        if request.current_user is None:","            abort(404)","        else:","            return jsonify(request.current_user.to_json())","    user = User.get(user_id)","    if user is None:","        abort(404)","    return jsonify(user.to_json())","","","@app_views.route('/users/<user_id>', methods=['DELETE'], strict_slashes=False)","def delete_user(user_id: str = None) -> str:","    \"\"\"DELETE /api/v1/users/:id","    Path parameter:","      - User ID.","    Return:","      - empty JSON is the User has been correctly deleted.","      - 404 if the User ID doesn't exist.","    \"\"\"","    if user_id is None:","        abort(404)","    user = User.get(user_id)","    if user is None:","        abort(404)","    user.remove()","    return jsonify({}), 200","","","@app_views.route('/users', methods=['POST'], strict_slashes=False)","def create_user() -> str:","    \"\"\"POST /api/v1/users/","    JSON body:","      - email.","      - password.","      - last_name (optional).","      - first_name (optional).","    Return:","      - User object JSON represented.","      - 400 if can't create the new User.","    \"\"\"","    rj = None","    error_msg = None","    try:","        rj = request.get_json()","    except Exception as e:","        rj = None","    if rj is None:","        error_msg = \"Wrong format\"","    if error_msg is None and rj.get(\"email\", \"\") == \"\":","        error_msg = \"email missing\"","    if error_msg is None and rj.get(\"password\", \"\") == \"\":","        error_msg = \"password missing\"","    if error_msg is None:","        try:","            user = User()","            user.email = rj.get(\"email\")","            user.password = rj.get(\"password\")","            user.first_name = rj.get(\"first_name\")","            user.last_name = rj.get(\"last_name\")","            user.save()","            return jsonify(user.to_json()), 201","        except Exception as e:","            error_msg = \"Can't create User: {}\".format(e)","    return jsonify({'error': error_msg}), 400","","","@app_views.route('/users/<user_id>', methods=['PUT'], strict_slashes=False)","def update_user(user_id: str = None) -> str:","    \"\"\"PUT /api/v1/users/:id","    Path parameter:","      - User ID.","    JSON body:","      - last_name (optional).","      - first_name (optional).","    Return:","      - User object JSON represented.","      - 404 if the User ID doesn't exist.","      - 400 if can't update the User.","    \"\"\"","    if user_id is None:","        abort(404)","    user = User.get(user_id)","    if user is None:","        abort(404)","    rj = None","    try:","        rj = request.get_json()","    except Exception as e:","        rj = None","    if rj is None:","        return jsonify({'error': \"Wrong format\"}), 400","    if rj.get('first_name') is not None:","        user.first_name = rj.get('first_name')","    if rj.get('last_name') is not None:","        user.last_name = rj.get('last_name')","    user.save()","    return jsonify(user.to_json()), 200"],"stylingDirectives":[[{"start":0,"end":22,"cssClass":"pl-c"}],[{"start":0,"end":25,"cssClass":"pl-s"}],[{"start":0,"end":3,"cssClass":"pl-s"}],[{"start":0,"end":4,"cssClass":"pl-k"},{"start":5,"end":8,"cssClass":"pl-s1"},{"start":9,"end":11,"cssClass":"pl-s1"},{"start":12,"end":17,"cssClass":"pl-s1"},{"start":18,"end":24,"cssClass":"pl-k"},{"start":25,"end":34,"cssClass":"pl-s1"}],[{"start":0,"end":4,"cssClass":"pl-k"},{"start":5,"end":10,"cssClass":"pl-s1"},{"start":11,"end":17,"cssClass":"pl-k"},{"start":18,"end":23,"cssClass":"pl-s1"},{"start":25,"end":32,"cssClass":"pl-s1"},{"start":34,"end":41,"cssClass":"pl-s1"}],[{"start":0,"end":4,"cssClass":"pl-k"},{"start":5,"end":11,"cssClass":"pl-s1"},{"start":12,"end":16,"cssClass":"pl-s1"},{"start":17,"end":23,"cssClass":"pl-k"},{"start":24,"end":28,"cssClass":"pl-v"}],[],[],[{"start":0,"end":65,"cssClass":"pl-en"},{"start":1,"end":10,"cssClass":"pl-s1"},{"start":11,"end":16,"cssClass":"pl-en"},{"start":17,"end":25,"cssClass":"pl-s"},{"start":27,"end":34,"cssClass":"pl-s1"},{"start":34,"end":35,"cssClass":"pl-c1"},{"start":36,"end":41,"cssClass":"pl-s"},{"start":44,"end":58,"cssClass":"pl-s1"},{"start":58,"end":59,"cssClass":"pl-c1"},{"start":59,"end":64,"cssClass":"pl-c1"}],[{"start":0,"end":3,"cssClass":"pl-k"},{"start":4,"end":18,"cssClass":"pl-en"},{"start":21,"end":23,"cssClass":"pl-c1"},{"start":24,"end":27,"cssClass":"pl-s1"}],[{"start":4,"end":24,"cssClass":"pl-s"}],[{"start":0,"end":11,"cssClass":"pl-s"}],[{"start":0,"end":50,"cssClass":"pl-s"}],[{"start":0,"end":7,"cssClass":"pl-s"}],[{"start":4,"end":13,"cssClass":"pl-s1"},{"start":14,"end":15,"cssClass":"pl-c1"},{"start":17,"end":21,"cssClass":"pl-s1"},{"start":22,"end":29,"cssClass":"pl-en"},{"start":32,"end":35,"cssClass":"pl-k"},{"start":36,"end":40,"cssClass":"pl-s1"},{"start":41,"end":43,"cssClass":"pl-c1"},{"start":44,"end":48,"cssClass":"pl-v"},{"start":49,"end":52,"cssClass":"pl-en"}],[{"start":4,"end":10,"cssClass":"pl-k"},{"start":11,"end":18,"cssClass":"pl-en"},{"start":19,"end":28,"cssClass":"pl-s1"}],[],[],[{"start":0,"end":75,"cssClass":"pl-en"},{"start":1,"end":10,"cssClass":"pl-s1"},{"start":11,"end":16,"cssClass":"pl-en"},{"start":17,"end":35,"cssClass":"pl-s"},{"start":37,"end":44,"cssClass":"pl-s1"},{"start":44,"end":45,"cssClass":"pl-c1"},{"start":46,"end":51,"cssClass":"pl-s"},{"start":54,"end":68,"cssClass":"pl-s1"},{"start":68,"end":69,"cssClass":"pl-c1"},{"start":69,"end":74,"cssClass":"pl-c1"}],[{"start":0,"end":3,"cssClass":"pl-k"},{"start":4,"end":17,"cssClass":"pl-en"},{"start":18,"end":25,"cssClass":"pl-s1"},{"start":27,"end":30,"cssClass":"pl-s1"},{"start":31,"end":32,"cssClass":"pl-c1"},{"start":33,"end":37,"cssClass":"pl-c1"},{"start":39,"end":41,"cssClass":"pl-c1"},{"start":42,"end":45,"cssClass":"pl-s1"}],[{"start":4,"end":28,"cssClass":"pl-s"}],[{"start":0,"end":19,"cssClass":"pl-s"}],[{"start":0,"end":16,"cssClass":"pl-s"}],[{"start":0,"end":11,"cssClass":"pl-s"}],[{"start":0,"end":37,"cssClass":"pl-s"}],[{"start":0,"end":41,"cssClass":"pl-s"}],[{"start":0,"end":7,"cssClass":"pl-s"}],[{"start":4,"end":6,"cssClass":"pl-k"},{"start":7,"end":14,"cssClass":"pl-s1"},{"start":15,"end":17,"cssClass":"pl-c1"},{"start":18,"end":22,"cssClass":"pl-c1"}],[{"start":8,"end":13,"cssClass":"pl-en"},{"start":14,"end":17,"cssClass":"pl-c1"}],[{"start":4,"end":6,"cssClass":"pl-k"},{"start":7,"end":14,"cssClass":"pl-s1"},{"start":15,"end":17,"cssClass":"pl-c1"},{"start":18,"end":22,"cssClass":"pl-s"}],[{"start":8,"end":10,"cssClass":"pl-k"},{"start":11,"end":18,"cssClass":"pl-s1"},{"start":19,"end":31,"cssClass":"pl-s1"},{"start":32,"end":34,"cssClass":"pl-c1"},{"start":35,"end":39,"cssClass":"pl-c1"}],[{"start":12,"end":17,"cssClass":"pl-en"},{"start":18,"end":21,"cssClass":"pl-c1"}],[{"start":8,"end":12,"cssClass":"pl-k"}],[{"start":12,"end":18,"cssClass":"pl-k"},{"start":19,"end":26,"cssClass":"pl-en"},{"start":27,"end":34,"cssClass":"pl-s1"},{"start":35,"end":47,"cssClass":"pl-s1"},{"start":48,"end":55,"cssClass":"pl-en"}],[{"start":4,"end":8,"cssClass":"pl-s1"},{"start":9,"end":10,"cssClass":"pl-c1"},{"start":11,"end":15,"cssClass":"pl-v"},{"start":16,"end":19,"cssClass":"pl-en"},{"start":20,"end":27,"cssClass":"pl-s1"}],[{"start":4,"end":6,"cssClass":"pl-k"},{"start":7,"end":11,"cssClass":"pl-s1"},{"start":12,"end":14,"cssClass":"pl-c1"},{"start":15,"end":19,"cssClass":"pl-c1"}],[{"start":8,"end":13,"cssClass":"pl-en"},{"start":14,"end":17,"cssClass":"pl-c1"}],[{"start":4,"end":10,"cssClass":"pl-k"},{"start":11,"end":18,"cssClass":"pl-en"},{"start":19,"end":23,"cssClass":"pl-s1"},{"start":24,"end":31,"cssClass":"pl-en"}],[],[],[{"start":0,"end":78,"cssClass":"pl-en"},{"start":1,"end":10,"cssClass":"pl-s1"},{"start":11,"end":16,"cssClass":"pl-en"},{"start":17,"end":35,"cssClass":"pl-s"},{"start":37,"end":44,"cssClass":"pl-s1"},{"start":44,"end":45,"cssClass":"pl-c1"},{"start":46,"end":54,"cssClass":"pl-s"},{"start":57,"end":71,"cssClass":"pl-s1"},{"start":71,"end":72,"cssClass":"pl-c1"},{"start":72,"end":77,"cssClass":"pl-c1"}],[{"start":0,"end":3,"cssClass":"pl-k"},{"start":4,"end":15,"cssClass":"pl-en"},{"start":16,"end":23,"cssClass":"pl-s1"},{"start":25,"end":28,"cssClass":"pl-s1"},{"start":29,"end":30,"cssClass":"pl-c1"},{"start":31,"end":35,"cssClass":"pl-c1"},{"start":37,"end":39,"cssClass":"pl-c1"},{"start":40,"end":43,"cssClass":"pl-s1"}],[{"start":4,"end":31,"cssClass":"pl-s"}],[{"start":0,"end":19,"cssClass":"pl-s"}],[{"start":0,"end":16,"cssClass":"pl-s"}],[{"start":0,"end":11,"cssClass":"pl-s"}],[{"start":0,"end":58,"cssClass":"pl-s"}],[{"start":0,"end":41,"cssClass":"pl-s"}],[{"start":0,"end":7,"cssClass":"pl-s"}],[{"start":4,"end":6,"cssClass":"pl-k"},{"start":7,"end":14,"cssClass":"pl-s1"},{"start":15,"end":17,"cssClass":"pl-c1"},{"start":18,"end":22,"cssClass":"pl-c1"}],[{"start":8,"end":13,"cssClass":"pl-en"},{"start":14,"end":17,"cssClass":"pl-c1"}],[{"start":4,"end":8,"cssClass":"pl-s1"},{"start":9,"end":10,"cssClass":"pl-c1"},{"start":11,"end":15,"cssClass":"pl-v"},{"start":16,"end":19,"cssClass":"pl-en"},{"start":20,"end":27,"cssClass":"pl-s1"}],[{"start":4,"end":6,"cssClass":"pl-k"},{"start":7,"end":11,"cssClass":"pl-s1"},{"start":12,"end":14,"cssClass":"pl-c1"},{"start":15,"end":19,"cssClass":"pl-c1"}],[{"start":8,"end":13,"cssClass":"pl-en"},{"start":14,"end":17,"cssClass":"pl-c1"}],[{"start":4,"end":8,"cssClass":"pl-s1"},{"start":9,"end":15,"cssClass":"pl-en"}],[{"start":4,"end":10,"cssClass":"pl-k"},{"start":11,"end":18,"cssClass":"pl-en"},{"start":24,"end":27,"cssClass":"pl-c1"}],[],[],[{"start":0,"end":66,"cssClass":"pl-en"},{"start":1,"end":10,"cssClass":"pl-s1"},{"start":11,"end":16,"cssClass":"pl-en"},{"start":17,"end":25,"cssClass":"pl-s"},{"start":27,"end":34,"cssClass":"pl-s1"},{"start":34,"end":35,"cssClass":"pl-c1"},{"start":36,"end":42,"cssClass":"pl-s"},{"start":45,"end":59,"cssClass":"pl-s1"},{"start":59,"end":60,"cssClass":"pl-c1"},{"start":60,"end":65,"cssClass":"pl-c1"}],[{"start":0,"end":3,"cssClass":"pl-k"},{"start":4,"end":15,"cssClass":"pl-en"},{"start":18,"end":20,"cssClass":"pl-c1"},{"start":21,"end":24,"cssClass":"pl-s1"}],[{"start":4,"end":26,"cssClass":"pl-s"}],[{"start":0,"end":14,"cssClass":"pl-s"}],[{"start":0,"end":14,"cssClass":"pl-s"}],[{"start":0,"end":17,"cssClass":"pl-s"}],[{"start":0,"end":29,"cssClass":"pl-s"}],[{"start":0,"end":30,"cssClass":"pl-s"}],[{"start":0,"end":11,"cssClass":"pl-s"}],[{"start":0,"end":37,"cssClass":"pl-s"}],[{"start":0,"end":41,"cssClass":"pl-s"}],[{"start":0,"end":7,"cssClass":"pl-s"}],[{"start":4,"end":6,"cssClass":"pl-s1"},{"start":7,"end":8,"cssClass":"pl-c1"},{"start":9,"end":13,"cssClass":"pl-c1"}],[{"start":4,"end":13,"cssClass":"pl-s1"},{"start":14,"end":15,"cssClass":"pl-c1"},{"start":16,"end":20,"cssClass":"pl-c1"}],[{"start":4,"end":7,"cssClass":"pl-k"}],[{"start":8,"end":10,"cssClass":"pl-s1"},{"start":11,"end":12,"cssClass":"pl-c1"},{"start":13,"end":20,"cssClass":"pl-s1"},{"start":21,"end":29,"cssClass":"pl-en"}],[{"start":4,"end":10,"cssClass":"pl-k"},{"start":11,"end":20,"cssClass":"pl-v"},{"start":21,"end":23,"cssClass":"pl-k"},{"start":24,"end":25,"cssClass":"pl-s1"}],[{"start":8,"end":10,"cssClass":"pl-s1"},{"start":11,"end":12,"cssClass":"pl-c1"},{"start":13,"end":17,"cssClass":"pl-c1"}],[{"start":4,"end":6,"cssClass":"pl-k"},{"start":7,"end":9,"cssClass":"pl-s1"},{"start":10,"end":12,"cssClass":"pl-c1"},{"start":13,"end":17,"cssClass":"pl-c1"}],[{"start":8,"end":17,"cssClass":"pl-s1"},{"start":18,"end":19,"cssClass":"pl-c1"},{"start":20,"end":34,"cssClass":"pl-s"}],[{"start":4,"end":6,"cssClass":"pl-k"},{"start":7,"end":16,"cssClass":"pl-s1"},{"start":17,"end":19,"cssClass":"pl-c1"},{"start":20,"end":24,"cssClass":"pl-c1"},{"start":25,"end":28,"cssClass":"pl-c1"},{"start":29,"end":31,"cssClass":"pl-s1"},{"start":32,"end":35,"cssClass":"pl-en"},{"start":36,"end":43,"cssClass":"pl-s"},{"start":45,"end":47,"cssClass":"pl-s"},{"start":49,"end":51,"cssClass":"pl-c1"},{"start":52,"end":54,"cssClass":"pl-s"}],[{"start":8,"end":17,"cssClass":"pl-s1"},{"start":18,"end":19,"cssClass":"pl-c1"},{"start":20,"end":35,"cssClass":"pl-s"}],[{"start":4,"end":6,"cssClass":"pl-k"},{"start":7,"end":16,"cssClass":"pl-s1"},{"start":17,"end":19,"cssClass":"pl-c1"},{"start":20,"end":24,"cssClass":"pl-c1"},{"start":25,"end":28,"cssClass":"pl-c1"},{"start":29,"end":31,"cssClass":"pl-s1"},{"start":32,"end":35,"cssClass":"pl-en"},{"start":36,"end":46,"cssClass":"pl-s"},{"start":48,"end":50,"cssClass":"pl-s"},{"start":52,"end":54,"cssClass":"pl-c1"},{"start":55,"end":57,"cssClass":"pl-s"}],[{"start":8,"end":17,"cssClass":"pl-s1"},{"start":18,"end":19,"cssClass":"pl-c1"},{"start":20,"end":38,"cssClass":"pl-s"}],[{"start":4,"end":6,"cssClass":"pl-k"},{"start":7,"end":16,"cssClass":"pl-s1"},{"start":17,"end":19,"cssClass":"pl-c1"},{"start":20,"end":24,"cssClass":"pl-c1"}],[{"start":8,"end":11,"cssClass":"pl-k"}],[{"start":12,"end":16,"cssClass":"pl-s1"},{"start":17,"end":18,"cssClass":"pl-c1"},{"start":19,"end":23,"cssClass":"pl-v"}],[{"start":12,"end":16,"cssClass":"pl-s1"},{"start":17,"end":22,"cssClass":"pl-s1"},{"start":23,"end":24,"cssClass":"pl-c1"},{"start":25,"end":27,"cssClass":"pl-s1"},{"start":28,"end":31,"cssClass":"pl-en"},{"start":32,"end":39,"cssClass":"pl-s"}],[{"start":12,"end":16,"cssClass":"pl-s1"},{"start":17,"end":25,"cssClass":"pl-s1"},{"start":26,"end":27,"cssClass":"pl-c1"},{"start":28,"end":30,"cssClass":"pl-s1"},{"start":31,"end":34,"cssClass":"pl-en"},{"start":35,"end":45,"cssClass":"pl-s"}],[{"start":12,"end":16,"cssClass":"pl-s1"},{"start":17,"end":27,"cssClass":"pl-s1"},{"start":28,"end":29,"cssClass":"pl-c1"},{"start":30,"end":32,"cssClass":"pl-s1"},{"start":33,"end":36,"cssClass":"pl-en"},{"start":37,"end":49,"cssClass":"pl-s"}],[{"start":12,"end":16,"cssClass":"pl-s1"},{"start":17,"end":26,"cssClass":"pl-s1"},{"start":27,"end":28,"cssClass":"pl-c1"},{"start":29,"end":31,"cssClass":"pl-s1"},{"start":32,"end":35,"cssClass":"pl-en"},{"start":36,"end":47,"cssClass":"pl-s"}],[{"start":12,"end":16,"cssClass":"pl-s1"},{"start":17,"end":21,"cssClass":"pl-en"}],[{"start":12,"end":18,"cssClass":"pl-k"},{"start":19,"end":26,"cssClass":"pl-en"},{"start":27,"end":31,"cssClass":"pl-s1"},{"start":32,"end":39,"cssClass":"pl-en"},{"start":44,"end":47,"cssClass":"pl-c1"}],[{"start":8,"end":14,"cssClass":"pl-k"},{"start":15,"end":24,"cssClass":"pl-v"},{"start":25,"end":27,"cssClass":"pl-k"},{"start":28,"end":29,"cssClass":"pl-s1"}],[{"start":12,"end":21,"cssClass":"pl-s1"},{"start":22,"end":23,"cssClass":"pl-c1"},{"start":24,"end":47,"cssClass":"pl-s"},{"start":48,"end":54,"cssClass":"pl-en"},{"start":55,"end":56,"cssClass":"pl-s1"}],[{"start":4,"end":10,"cssClass":"pl-k"},{"start":11,"end":18,"cssClass":"pl-en"},{"start":20,"end":27,"cssClass":"pl-s"},{"start":29,"end":38,"cssClass":"pl-s1"},{"start":42,"end":45,"cssClass":"pl-c1"}],[],[],[{"start":0,"end":75,"cssClass":"pl-en"},{"start":1,"end":10,"cssClass":"pl-s1"},{"start":11,"end":16,"cssClass":"pl-en"},{"start":17,"end":35,"cssClass":"pl-s"},{"start":37,"end":44,"cssClass":"pl-s1"},{"start":44,"end":45,"cssClass":"pl-c1"},{"start":46,"end":51,"cssClass":"pl-s"},{"start":54,"end":68,"cssClass":"pl-s1"},{"start":68,"end":69,"cssClass":"pl-c1"},{"start":69,"end":74,"cssClass":"pl-c1"}],[{"start":0,"end":3,"cssClass":"pl-k"},{"start":4,"end":15,"cssClass":"pl-en"},{"start":16,"end":23,"cssClass":"pl-s1"},{"start":25,"end":28,"cssClass":"pl-s1"},{"start":29,"end":30,"cssClass":"pl-c1"},{"start":31,"end":35,"cssClass":"pl-c1"},{"start":37,"end":39,"cssClass":"pl-c1"},{"start":40,"end":43,"cssClass":"pl-s1"}],[{"start":4,"end":28,"cssClass":"pl-s"}],[{"start":0,"end":19,"cssClass":"pl-s"}],[{"start":0,"end":16,"cssClass":"pl-s"}],[{"start":0,"end":14,"cssClass":"pl-s"}],[{"start":0,"end":29,"cssClass":"pl-s"}],[{"start":0,"end":30,"cssClass":"pl-s"}],[{"start":0,"end":11,"cssClass":"pl-s"}],[{"start":0,"end":37,"cssClass":"pl-s"}],[{"start":0,"end":41,"cssClass":"pl-s"}],[{"start":0,"end":37,"cssClass":"pl-s"}],[{"start":0,"end":7,"cssClass":"pl-s"}],[{"start":4,"end":6,"cssClass":"pl-k"},{"start":7,"end":14,"cssClass":"pl-s1"},{"start":15,"end":17,"cssClass":"pl-c1"},{"start":18,"end":22,"cssClass":"pl-c1"}],[{"start":8,"end":13,"cssClass":"pl-en"},{"start":14,"end":17,"cssClass":"pl-c1"}],[{"start":4,"end":8,"cssClass":"pl-s1"},{"start":9,"end":10,"cssClass":"pl-c1"},{"start":11,"end":15,"cssClass":"pl-v"},{"start":16,"end":19,"cssClass":"pl-en"},{"start":20,"end":27,"cssClass":"pl-s1"}],[{"start":4,"end":6,"cssClass":"pl-k"},{"start":7,"end":11,"cssClass":"pl-s1"},{"start":12,"end":14,"cssClass":"pl-c1"},{"start":15,"end":19,"cssClass":"pl-c1"}],[{"start":8,"end":13,"cssClass":"pl-en"},{"start":14,"end":17,"cssClass":"pl-c1"}],[{"start":4,"end":6,"cssClass":"pl-s1"},{"start":7,"end":8,"cssClass":"pl-c1"},{"start":9,"end":13,"cssClass":"pl-c1"}],[{"start":4,"end":7,"cssClass":"pl-k"}],[{"start":8,"end":10,"cssClass":"pl-s1"},{"start":11,"end":12,"cssClass":"pl-c1"},{"start":13,"end":20,"cssClass":"pl-s1"},{"start":21,"end":29,"cssClass":"pl-en"}],[{"start":4,"end":10,"cssClass":"pl-k"},{"start":11,"end":20,"cssClass":"pl-v"},{"start":21,"end":23,"cssClass":"pl-k"},{"start":24,"end":25,"cssClass":"pl-s1"}],[{"start":8,"end":10,"cssClass":"pl-s1"},{"start":11,"end":12,"cssClass":"pl-c1"},{"start":13,"end":17,"cssClass":"pl-c1"}],[{"start":4,"end":6,"cssClass":"pl-k"},{"start":7,"end":9,"cssClass":"pl-s1"},{"start":10,"end":12,"cssClass":"pl-c1"},{"start":13,"end":17,"cssClass":"pl-c1"}],[{"start":8,"end":14,"cssClass":"pl-k"},{"start":15,"end":22,"cssClass":"pl-en"},{"start":24,"end":31,"cssClass":"pl-s"},{"start":33,"end":47,"cssClass":"pl-s"},{"start":51,"end":54,"cssClass":"pl-c1"}],[{"start":4,"end":6,"cssClass":"pl-k"},{"start":7,"end":9,"cssClass":"pl-s1"},{"start":10,"end":13,"cssClass":"pl-en"},{"start":14,"end":26,"cssClass":"pl-s"},{"start":28,"end":30,"cssClass":"pl-c1"},{"start":31,"end":34,"cssClass":"pl-c1"},{"start":35,"end":39,"cssClass":"pl-c1"}],[{"start":8,"end":12,"cssClass":"pl-s1"},{"start":13,"end":23,"cssClass":"pl-s1"},{"start":24,"end":25,"cssClass":"pl-c1"},{"start":26,"end":28,"cssClass":"pl-s1"},{"start":29,"end":32,"cssClass":"pl-en"},{"start":33,"end":45,"cssClass":"pl-s"}],[{"start":4,"end":6,"cssClass":"pl-k"},{"start":7,"end":9,"cssClass":"pl-s1"},{"start":10,"end":13,"cssClass":"pl-en"},{"start":14,"end":25,"cssClass":"pl-s"},{"start":27,"end":29,"cssClass":"pl-c1"},{"start":30,"end":33,"cssClass":"pl-c1"},{"start":34,"end":38,"cssClass":"pl-c1"}],[{"start":8,"end":12,"cssClass":"pl-s1"},{"start":13,"end":22,"cssClass":"pl-s1"},{"start":23,"end":24,"cssClass":"pl-c1"},{"start":25,"end":27,"cssClass":"pl-s1"},{"start":28,"end":31,"cssClass":"pl-en"},{"start":32,"end":43,"cssClass":"pl-s"}],[{"start":4,"end":8,"cssClass":"pl-s1"},{"start":9,"end":13,"cssClass":"pl-en"}],[{"start":4,"end":10,"cssClass":"pl-k"},{"start":11,"end":18,"cssClass":"pl-en"},{"start":19,"end":23,"cssClass":"pl-s1"},{"start":24,"end":31,"cssClass":"pl-en"},{"start":36,"end":39,"cssClass":"pl-c1"}]],"csv":null,"csvError":null,"dependabotInfo":{"showConfigurationBanner":false,"configFilePath":null,"networkDependabotPath":"/Blackhat-red-team/alx-backend-user-data/network/updates","dismissConfigurationNoticePath":"/settings/dismiss-notice/dependabot_configuration_notice","configurationNoticeDismissed":null},"displayName":"users.py","displayUrl":"https://github.com/Blackhat-red-team/alx-backend-user-data/blob/main/0x02-Session_authentication/api/v1/views/users.py?raw=true","headerInfo":{"blobSize":"3.5 KB","deleteTooltip":"You must be signed in to make or propose changes","editTooltip":"You must be signed in to make or propose changes","deleteInfo":{"deleteTooltip":"You must be signed in to make or propose changes"},"editInfo":{"editTooltip":"You must be signed in to make or propose changes"},"ghDesktopPath":"https://desktop.github.com","isGitLfs":false,"gitLfsPath":null,"onBranch":true,"shortPath":"bfe0101","siteNavLoginPath":"/login?return_to=https%3A%2F%2Fgithub.com%2FBlackhat-red-team%2Falx-backend-user-data%2Fblob%2Fmain%2F0x02-Session_authentication%2Fapi%2Fv1%2Fviews%2Fusers.py","isCSV":false,"isRichtext":false,"toc":null,"lineInfo":{"truncatedLoc":"127","truncatedSloc":"117"},"mode":"executable file"},"image":false,"isCodeownersFile":null,"isPlain":false,"isValidLegacyIssueTemplate":false,"issueTemplateHelpUrl":"https://docs.github.com/articles/about-issue-and-pull-request-templates","issueTemplate":null,"discussionTemplate":null,"language":"Python","languageID":303,"large":false,"loggedIn":false,"planSupportInfo":{"repoIsFork":null,"repoOwnedByCurrentUser":null,"requestFullPath":"/Blackhat-red-team/alx-backend-user-data/blob/main/0x02-Session_authentication/api/v1/views/users.py","showFreeOrgGatedFeatureMessage":null,"showPlanSupportBanner":null,"upgradeDataAttributes":null,"upgradePath":null},"publishBannersInfo":{"dismissActionNoticePath":"/settings/dismiss-notice/publish_action_from_dockerfile","releasePath":"/Blackhat-red-team/alx-backend-user-data/releases/new?marketplace=true","showPublishActionBanner":false},"rawBlobUrl":"https://github.com/Blackhat-red-team/alx-backend-user-data/raw/main/0x02-Session_authentication/api/v1/views/users.py","renderImageOrRaw":false,"richText":null,"renderedFileInfo":null,"shortPath":null,"symbolsEnabled":true,"tabSize":8,"topBannersInfo":{"overridingGlobalFundingFile":false,"globalPreferredFundingPath":null,"repoOwner":"Blackhat-red-team","repoName":"alx-backend-user-data","showInvalidCitationWarning":false,"citationHelpUrl":"https://docs.github.com/github/creating-cloning-and-archiving-repositories/creating-a-repository-on-github/about-citation-files","actionsOnboardingTip":null},"truncated":false,"viewable":true,"workflowRedirectUrl":null,"symbols":{"timed_out":false,"not_analyzed":false,"symbols":[{"name":"view_all_users","kind":"function","ident_start":231,"ident_end":245,"extent_start":227,"extent_end":437,"fully_qualified_name":"view_all_users","ident_utf16":{"start":{"line_number":9,"utf16_col":4},"end":{"line_number":9,"utf16_col":18}},"extent_utf16":{"start":{"line_number":9,"utf16_col":0},"end":{"line_number":15,"utf16_col":29}}},{"name":"view_one_user","kind":"function","ident_start":520,"ident_end":533,"extent_start":516,"extent_end":1036,"fully_qualified_name":"view_one_user","ident_utf16":{"start":{"line_number":19,"utf16_col":4},"end":{"line_number":19,"utf16_col":17}},"extent_utf16":{"start":{"line_number":19,"utf16_col":0},"end":{"line_number":37,"utf16_col":34}}},{"name":"delete_user","kind":"function","ident_start":1122,"ident_end":1133,"extent_start":1118,"extent_end":1510,"fully_qualified_name":"delete_user","ident_utf16":{"start":{"line_number":41,"utf16_col":4},"end":{"line_number":41,"utf16_col":15}},"extent_utf16":{"start":{"line_number":41,"utf16_col":0},"end":{"line_number":55,"utf16_col":27}}},{"name":"create_user","kind":"function","ident_start":1584,"ident_end":1595,"extent_start":1580,"extent_end":2666,"fully_qualified_name":"create_user","ident_utf16":{"start":{"line_number":59,"utf16_col":4},"end":{"line_number":59,"utf16_col":15}},"extent_utf16":{"start":{"line_number":59,"utf16_col":0},"end":{"line_number":93,"utf16_col":45}}},{"name":"update_user","kind":"function","ident_start":2749,"ident_end":2760,"extent_start":2745,"extent_end":3584,"fully_qualified_name":"update_user","ident_utf16":{"start":{"line_number":97,"utf16_col":4},"end":{"line_number":97,"utf16_col":15}},"extent_utf16":{"start":{"line_number":97,"utf16_col":0},"end":{"line_number":126,"utf16_col":39}}}]}},"copilotInfo":null,"copilotAccessAllowed":false,"csrf_tokens":{"/Blackhat-red-team/alx-backend-user-data/branches":{"post":"AgIFN_toMILul8Ru0gwZooFhj9Vq3sRkMkJ4ryEEYokJkNnd8EzsvNtbMjXAAyJnw7bfSk3nzhRAt3046X4Njg"},"/repos/preferences":{"post":"lXb-AE7rymAM4xesmxIuezlR3G2p6A7S7zS0N7aZZYltjq7CLPkRVTjHjQE49SVOrTpbybWpnIfwnmdB9ZLBQg"}}},"title":"alx-backend-user-data/0x02-Session_authentication/api/v1/views/users.py at main · Blackhat-red-team/alx-backend-user-data"}