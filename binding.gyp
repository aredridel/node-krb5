{
  'targets': [
    {
      'target_name': 'krb5',
      'sources': [ 'src/krb5.cc' ],
      'link_settings' : {
        'libraries': [ '-lkrb5' ]
      }
    },
  ]
}
