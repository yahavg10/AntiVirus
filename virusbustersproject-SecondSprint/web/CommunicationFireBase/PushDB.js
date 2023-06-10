//push md5 of file scanned and found sus
set(ref(db, 'Files/'), {
    userRes : userId,
    md5: Filemd5,
    Danger : isDanger ? "True" : "False"
  });

